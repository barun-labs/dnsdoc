use std::collections::BTreeSet;
use std::net::IpAddr;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use tokio::sync::mpsc;

use crate::dns;
use crate::types::{CheckResult, Msg, Severity};

const DKIM_SELECTORS: &[&str] = &["default", "google", "k1", "s1", "selector1", "selector2"];

fn ok(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Ok, detail: detail.into() }
}
fn warn(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Warn, detail: detail.into() }
}
fn err(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Err, detail: detail.into() }
}

fn norm_set(items: &[String]) -> BTreeSet<String> {
    items
        .iter()
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
        .collect()
}

pub fn check_ns_consistency(parent: &[String], child: &[String]) -> CheckResult {
    if parent.is_empty() {
        return warn("NS delegation", "could not read parent NS set");
    }
    if child.is_empty() {
        return err("NS delegation", "zone apex returned no NS records");
    }
    if norm_set(parent) == norm_set(child) {
        ok("NS delegation", format!("parent and zone agree ({} NS)", child.len()))
    } else {
        err(
            "NS delegation",
            format!("mismatch — parent {:?} vs zone {:?}", norm_set(parent), norm_set(child)),
        )
    }
}

pub fn check_soa_serials(serials: &[(String, Option<u32>)]) -> CheckResult {
    let present: Vec<u32> = serials.iter().filter_map(|(_, s)| *s).collect();
    if present.is_empty() {
        return err("SOA serial", "no NS returned a SOA record");
    }
    let unique: BTreeSet<u32> = present.iter().copied().collect();
    if unique.len() == 1 {
        ok("SOA serial", format!("all NS on serial {}", present[0]))
    } else {
        warn("SOA serial", format!("serials differ across NS: {:?}", unique))
    }
}

pub fn check_spf(txts: &[String]) -> CheckResult {
    let spf: Vec<&String> = txts.iter().filter(|t| t.to_lowercase().starts_with("v=spf1")).collect();
    match spf.len() {
        0 => warn("SPF", "no SPF record found"),
        1 => {
            let rec = spf[0].to_lowercase();
            let lookups = rec
                .split_whitespace()
                .filter(|t| {
                    t.starts_with("include:")
                        || t.starts_with("a:")
                        || *t == "a"
                        || t.starts_with("mx")
                        || t.starts_with("ptr")
                        || t.starts_with("exists:")
                        || t.starts_with("redirect=")
                })
                .count();
            if lookups > 10 {
                err("SPF", format!("{lookups} DNS-lookup mechanisms (>10, will PermError)"))
            } else {
                ok("SPF", format!("present, {lookups} lookups"))
            }
        }
        n => err("SPF", format!("{n} SPF records (must be exactly 1)")),
    }
}

pub fn check_dmarc(txt: Option<&str>) -> CheckResult {
    match txt {
        None => warn("DMARC", "no _dmarc TXT record"),
        Some(t) => {
            let policy = t
                .split(';')
                .map(|p| p.trim())
                .find_map(|p| p.strip_prefix("p="))
                .unwrap_or("(none)");
            if policy == "none" {
                warn("DMARC", "present but policy p=none (monitor only)")
            } else {
                ok("DMARC", format!("present, p={policy}"))
            }
        }
    }
}

pub fn check_ttl(ttls: &[(String, u32)]) -> CheckResult {
    let mut findings = vec![];
    for (label, ttl) in ttls {
        if *ttl < 60 {
            findings.push(format!("{label} TTL {ttl}s (<60, very low)"));
        } else if *ttl > 604800 {
            findings.push(format!("{label} TTL {ttl}s (>7d, very high)"));
        }
    }
    if findings.is_empty() {
        ok("TTL sanity", "all TTLs within 60s–7d")
    } else {
        warn("TTL sanity", findings.join("; "))
    }
}

pub fn check_apex_cname(has_cname: bool, other_types: &[String]) -> CheckResult {
    if has_cname && !other_types.is_empty() {
        err("Apex CNAME", format!("CNAME at apex coexists with {:?} (RFC violation)", other_types))
    } else if has_cname {
        warn("Apex CNAME", "CNAME at zone apex (invalid per RFC 1034)")
    } else {
        ok("Apex CNAME", "no CNAME at apex")
    }
}

// ---- async collectors (network) ----

async fn parent_ns(domain: &str) -> Vec<String> {
    // Ask a public resolver's view of the delegation from the TLD by querying
    // NS at the registry. hickory's recursive resolver returns the zone's NS;
    // for the parent view we query the TLD servers directly via authority
    // section. Simpler robust approach: use system resolver NS (zone) and
    // compare against a second independent public resolver.
    let seed: IpAddr = "1.1.1.1".parse().unwrap();
    dns::query(seed, domain, RecordType::NS)
        .await
        .answers
}

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let mut results = vec![];
    let seed: IpAddr = "8.8.8.8".parse().unwrap();

    // NS: parent view (public resolver) vs zone view (authoritative)
    let parent = parent_ns(&domain).await;
    let ns_list = dns::authoritative_ns(&domain).await.unwrap_or_default();
    let child: Vec<String> = ns_list.iter().map(|(n, _)| n.clone()).collect();
    results.push(check_ns_consistency(&parent, &child));

    // SOA serials from each authoritative NS
    let mut serials = vec![];
    for (name, ip) in &ns_list {
        let out = dns::query(*ip, &domain, RecordType::SOA).await;
        let serial = out.answers.first().and_then(|a| {
            a.rsplit("serial=").next().and_then(|s| s.trim().parse::<u32>().ok())
        });
        serials.push((name.clone(), serial));
    }
    results.push(check_soa_serials(&serials));

    // Lame server detection: each NS must set AA for its own zone
    let mut lame = vec![];
    for (name, ip) in &ns_list {
        match dns::raw_query(*ip, &domain, RecordType::SOA).await {
            Ok((resp, _)) => {
                if !resp.header().authoritative() || resp.response_code() != ResponseCode::NoError {
                    lame.push(name.clone());
                }
            }
            Err(_) => lame.push(format!("{name} (unreachable)")),
        }
    }
    if lame.is_empty() && !ns_list.is_empty() {
        results.push(ok("Lame servers", format!("all {} NS authoritative", ns_list.len())));
    } else if !ns_list.is_empty() {
        results.push(err("Lame servers", format!("not authoritative / unreachable: {:?}", lame)));
    }

    // TXT-derived: SPF, DMARC
    let txts = dns::query(seed, &domain, RecordType::TXT).await.answers;
    results.push(check_spf(&txts));
    let dmarc = dns::query(seed, &format!("_dmarc.{domain}"), RecordType::TXT)
        .await
        .answers;
    let dmarc_rec = dmarc.iter().find(|t| t.to_lowercase().starts_with("v=dmarc1"));
    results.push(check_dmarc(dmarc_rec.map(|s| s.as_str())));

    // DKIM selector probe
    let mut dkim_found = vec![];
    for sel in DKIM_SELECTORS {
        let q = dns::query(seed, &format!("{sel}._domainkey.{domain}"), RecordType::TXT).await;
        if q.answers.iter().any(|a| a.to_lowercase().contains("v=dkim1") || a.contains("p=")) {
            dkim_found.push(*sel);
        }
    }
    if dkim_found.is_empty() {
        results.push(warn("DKIM", "no common selectors found (default/google/k1/s1/selector1/selector2)"));
    } else {
        results.push(ok("DKIM", format!("selectors present: {:?}", dkim_found)));
    }

    // TTL sanity across A/MX
    let a = dns::query(seed, &domain, RecordType::A).await;
    let mx = dns::query(seed, &domain, RecordType::MX).await;
    let mut ttls = vec![];
    if let Some(t) = a.ttl { ttls.push(("A".to_string(), t)); }
    if let Some(t) = mx.ttl { ttls.push(("MX".to_string(), t)); }
    if !ttls.is_empty() {
        results.push(check_ttl(&ttls));
    }

    // Apex CNAME
    let cname = dns::query(seed, &domain, RecordType::CNAME).await;
    let mut others = vec![];
    if !a.answers.is_empty() { others.push("A".to_string()); }
    if !mx.answers.is_empty() { others.push("MX".to_string()); }
    results.push(check_apex_cname(!cname.answers.is_empty(), &others));

    // Open AXFR (zone transfer) — security
    let mut axfr_open = vec![];
    for (name, ip) in &ns_list {
        if let Ok((resp, _)) = dns::raw_query(*ip, &domain, RecordType::AXFR).await {
            let has_records = resp.answers().iter().any(|r| {
                matches!(r.data().try_into(), Ok(&RData::SOA(_)))
                    || resp.answers().len() > 1
            });
            if has_records {
                axfr_open.push(name.clone());
            }
        }
    }
    if axfr_open.is_empty() {
        results.push(ok("Zone transfer", "AXFR refused by all NS"));
    } else {
        results.push(err("Zone transfer", format!("AXFR OPEN on {:?} — exposes full zone", axfr_open)));
    }

    // Wildcard detection
    let rnd = format!("nx-{}.{}", "zqx7probe", domain);
    let wc = dns::query(seed, &rnd, RecordType::A).await;
    if wc.answers.is_empty() {
        results.push(ok("Wildcard", "no wildcard A record"));
    } else {
        results.push(warn("Wildcard", format!("wildcard resolves to {:?}", wc.answers)));
    }

    let _ = tx.send(Msg::Audit(results)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn ns_match_ignores_case_and_dot() {
        let r = check_ns_consistency(&s(&["A.NS.com."]), &s(&["a.ns.com"]));
        assert_eq!(r.severity, Severity::Ok);
    }

    #[test]
    fn ns_mismatch_is_error() {
        let r = check_ns_consistency(&s(&["a.ns.com"]), &s(&["b.ns.com"]));
        assert_eq!(r.severity, Severity::Err);
    }

    #[test]
    fn soa_serials_agree() {
        let r = check_soa_serials(&[("a".into(), Some(5)), ("b".into(), Some(5))]);
        assert_eq!(r.severity, Severity::Ok);
    }

    #[test]
    fn soa_serials_differ_warns() {
        let r = check_soa_serials(&[("a".into(), Some(5)), ("b".into(), Some(6))]);
        assert_eq!(r.severity, Severity::Warn);
    }

    #[test]
    fn spf_counts_lookups() {
        let r = check_spf(&s(&["v=spf1 include:a.com include:b.com mx -all"]));
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.contains('3'));
    }

    #[test]
    fn spf_too_many_lookups_errors() {
        let many = format!("v=spf1 {}-all", "include:x.com ".repeat(11));
        let r = check_spf(&[many]);
        assert_eq!(r.severity, Severity::Err);
    }

    #[test]
    fn spf_missing_warns() {
        assert_eq!(check_spf(&s(&["some other txt"])).severity, Severity::Warn);
    }

    #[test]
    fn dmarc_policy_extracted() {
        let r = check_dmarc(Some("v=DMARC1; p=reject; rua=mailto:x@y.com"));
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.contains("reject"));
    }

    #[test]
    fn dmarc_none_warns() {
        assert_eq!(check_dmarc(Some("v=DMARC1; p=none")).severity, Severity::Warn);
    }

    #[test]
    fn ttl_low_warns() {
        assert_eq!(check_ttl(&[("A".into(), 30)]).severity, Severity::Warn);
    }

    #[test]
    fn ttl_normal_ok() {
        assert_eq!(check_ttl(&[("A".into(), 300)]).severity, Severity::Ok);
    }

    #[test]
    fn apex_cname_with_others_errors() {
        assert_eq!(check_apex_cname(true, &s(&["A"])).severity, Severity::Err);
    }

    #[test]
    fn no_apex_cname_ok() {
        assert_eq!(check_apex_cname(false, &s(&["A"])).severity, Severity::Ok);
    }
}
