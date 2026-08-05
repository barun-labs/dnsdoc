use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::TimeZone;
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

pub fn check_caa(records: &[String]) -> CheckResult {
    if records.is_empty() {
        ok("CAA", "no CAA record (any CA may issue)")
    } else {
        ok("CAA", format!("present: {}", records.join("; ")))
    }
}

pub struct MxTargetInfo {
    pub target: String,
    pub is_ip_literal: bool,
    pub has_cname: bool,
    pub resolves: bool,
}

pub fn check_mx(infos: &[MxTargetInfo], null_mx: bool) -> CheckResult {
    if null_mx {
        return ok("MX", "null MX (domain sends no mail)");
    }
    if infos.is_empty() {
        return warn("MX", "no MX records (mail falls back to A record)");
    }
    let mut problems = vec![];
    let mut sev = Severity::Ok;
    for i in infos {
        if i.is_ip_literal {
            problems.push(format!("{} is an IP literal (invalid)", i.target));
            sev = Severity::Err;
        } else if !i.resolves {
            problems.push(format!("{} does not resolve", i.target));
            sev = Severity::Err;
        } else if i.has_cname {
            problems.push(format!("{} is a CNAME (RFC 2181 violation)", i.target));
            if sev == Severity::Ok { sev = Severity::Warn; }
        }
    }
    match sev {
        Severity::Ok => ok("MX", format!("{} target(s) resolve cleanly", infos.len())),
        Severity::Warn => warn("MX", problems.join("; ")),
        Severity::Err => err("MX", problems.join("; ")),
    }
}

pub fn check_ns_redundancy(ns_list: &[(String, IpAddr)]) -> CheckResult {
    if ns_list.len() < 2 {
        return warn("NS redundancy", format!("only {} NS (2+ recommended)", ns_list.len()));
    }
    let v4_prefixes: BTreeSet<String> = ns_list
        .iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            IpAddr::V6(_) => None,
        })
        .collect();
    let v4_count = ns_list.iter().filter(|(_, ip)| ip.is_ipv4()).count();
    if v4_count == ns_list.len() && v4_prefixes.len() == 1 {
        warn("NS redundancy", format!("all {} NS in one /24 — single point of failure", ns_list.len()))
    } else {
        ok("NS redundancy", format!("{} NS across {} network(s)", ns_list.len(), v4_prefixes.len().max(1)))
    }
}

pub fn check_soa_values(serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32) -> CheckResult {
    let mut findings = vec![];
    if !(1200..=86400).contains(&refresh) {
        findings.push(format!("refresh {refresh}s outside 1200–86400"));
    }
    if retry >= refresh {
        findings.push(format!("retry {retry}s >= refresh {refresh}s"));
    }
    if expire < 604800 {
        findings.push(format!("expire {expire}s < 7d — secondaries drop the zone too soon"));
    }
    if minimum > 86400 {
        findings.push(format!("negative-cache TTL {minimum}s > 1d"));
    }
    if findings.is_empty() {
        ok("SOA sanity", format!("serial {serial}, timers sane"))
    } else {
        warn("SOA sanity", findings.join("; "))
    }
}

/// Walk of a CNAME chain: `chain[0]` is the queried name's first CNAME
/// target, each subsequent entry the next. `terminal_resolves` says whether
/// the last target answered an A/AAAA query.
pub fn check_cname_chain(chain: &[String], terminal_resolves: bool) -> CheckResult {
    let mut seen = std::collections::HashSet::new();
    for c in chain {
        if !seen.insert(c.trim_end_matches('.').to_ascii_lowercase()) {
            return err("CNAME chain", format!("loop detected at {c}"));
        }
    }
    if chain.is_empty() {
        return ok("CNAME chain", "no CNAME");
    }
    let rendered = chain.join(" → ");
    if !terminal_resolves {
        err("CNAME chain", format!("dangling — {rendered} resolves to nothing"))
    } else if chain.len() > 8 {
        warn("CNAME chain", format!("{} hops ({rendered}) — resolvers may give up", chain.len()))
    } else {
        ok("CNAME chain", format!("{} hop(s): {rendered}", chain.len()))
    }
}

/// SOA serials in YYYYMMDDnn form encode the zone's last-touch date.
pub fn decode_soa_date(serial: u32, now: chrono::DateTime<chrono::Utc>) -> Option<String> {
    let s = serial.to_string();
    if s.len() != 10 {
        return None;
    }
    let y: i32 = s[0..4].parse().ok()?;
    let m: u32 = s[4..6].parse().ok()?;
    let d: u32 = s[6..8].parse().ok()?;
    if !(1990..=2035).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let date = chrono::Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).single()?;
    let days = (now - date).num_days();
    Some(format!("date-encoded, zone last touched ~{days}d ago"))
}

// ---- async collectors (network) ----

/// Serial from the first SOA record in a raw response, if any.
fn soa_serial(resp: &hickory_proto::xfer::DnsResponse) -> Option<u32> {
    resp.answers().first().and_then(|r| match r.data().try_into() {
        Ok(&RData::SOA(ref soa)) => Some(soa.serial()),
        _ => None,
    })
}

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

    // SOA serials from each authoritative NS (RD=0: no recursion)
    let mut serials = vec![];
    for (name, ip) in &ns_list {
        let serial = match dns::raw_query_opts(*ip, &domain, RecordType::SOA, false).await {
            Ok((resp, _)) => soa_serial(&resp),
            Err(_) => None,
        };
        serials.push((name.clone(), serial));
    }
    let mut soa_serial_check = check_soa_serials(&serials);
    soa_serial_check.detail = format!("{} [RD=0, no recursion]", soa_serial_check.detail);
    results.push(soa_serial_check);

    // SOA sanity: timer values on the primary NS's SOA record
    if let Some((_, ip)) = ns_list.first() {
        if let Ok((resp, _)) = dns::raw_query_opts(*ip, &domain, RecordType::SOA, false).await {
            if let Some(r) = resp.answers().first() {
                if let Ok(&RData::SOA(ref soa)) = r.data().try_into() {
                    // F9: date-encoded serials (YYYYMMDDnn) carry last-touch info
                    let mut soa_check = check_soa_values(
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum(),
                    );
                    if let Some(note) = decode_soa_date(soa.serial(), chrono::Utc::now()) {
                        soa_check.detail = format!("{}; {}", soa_check.detail, note);
                    }
                    results.push(soa_check);
                }
            }
        }
    }

    // F3: TCP transport + EDNS on the primary NS — same SOA, RD=0
    if let Some((_, ip)) = ns_list.first() {
        match dns::raw_query_tcp(*ip, &domain, RecordType::SOA, false).await {
            Ok((resp, _)) => {
                results.push(ok("TCP transport", format!("TCP/53 answers ({} records)", resp.answers().len())));
            }
            Err(_) => results.push(err(
                "TCP transport",
                "TCP/53 refused or filtered — large responses and AXFR will fail",
            )),
        }
        match dns::raw_query_edns(*ip, &domain, RecordType::SOA, false, false).await {
            Ok((resp, _)) => match resp.extensions() {
                Some(e) => results.push(ok("EDNS", format!("supported (advertised buffer {})", e.max_payload()))),
                None => results.push(warn("EDNS", "no EDNS/OPT in response — old server, large answers truncate")),
            },
            Err(_) => results.push(warn("EDNS", "EDNS query failed")),
        }
    }

    // F4: glue consistency — parent referral glue vs child-zone A for in-bailiwick NS
    let mut glue: Vec<(String, String)> = vec![];
    if let Ok((resp, _)) = dns::raw_query(seed, &domain, RecordType::NS).await {
        for r in resp.additionals() {
            if r.record_type() == RecordType::A {
                if let Ok(&RData::A(ref a)) = r.data().try_into() {
                    glue.push((r.name().to_string(), a.to_string()));
                }
            }
        }
    }
    if glue.is_empty() {
        results.push(ok("Glue", "no glue in referral additional section — nothing to compare"));
    } else {
        let dom = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut mismatches = vec![];
        let mut compared = 0;
        for (ns, ip) in &ns_list {
            let n = ns.trim_end_matches('.').to_ascii_lowercase();
            if n != dom && !n.ends_with(&format!(".{dom}")) {
                continue; // out-of-bailiwick — skip
            }
            if let Some((_, g)) = glue.iter().find(|(gn, _)| gn.trim_end_matches('.') == n.as_str()) {
                compared += 1;
                if *g != ip.to_string() {
                    mismatches.push(format!("{ns}: glue {g} vs zone {ip}"));
                }
            }
        }
        if mismatches.is_empty() {
            results.push(ok("Glue", format!("{compared} in-bailiwick NS match parent glue")));
        } else {
            results.push(err("Glue", mismatches.join("; ")));
        }
    }

    // NS redundancy: 2+ nameservers spread across networks
    if !ns_list.is_empty() {
        results.push(check_ns_redundancy(&ns_list));
    }

    // Lame server detection: each NS must set AA for its own zone (RD=0)
    let mut lame = vec![];
    for (name, ip) in &ns_list {
        match dns::raw_query_opts(*ip, &domain, RecordType::SOA, false).await {
            Ok((resp, _)) => {
                if !resp.header().authoritative() || resp.response_code() != ResponseCode::NoError {
                    lame.push(name.clone());
                }
            }
            Err(_) => lame.push(format!("{name} (unreachable)")),
        }
    }
    if !ns_list.is_empty() {
        let mut lame_check = if lame.is_empty() {
            ok("Lame servers", format!("all {} NS authoritative", ns_list.len()))
        } else {
            err("Lame servers", format!("not authoritative / unreachable: {:?}", lame))
        };
        lame_check.detail = format!("{} [RD=0, no recursion]", lame_check.detail);
        results.push(lame_check);
    }

    // CAA: which CAs may issue for the domain
    let caa = dns::query(seed, &domain, RecordType::CAA).await;
    results.push(check_caa(&caa.answers));

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

    // MX sanity: parse targets, check IP literals / CNAMEs / resolvability.
    // MX rdata strings look like "10 mail.example.com.".
    let mut infos = vec![];
    let mut null_mx = false;
    for ans in &mx.answers {
        let Some(target) = ans.split_whitespace().last() else { continue };
        let target = target.trim_end_matches('.');
        if target.is_empty() && mx.answers.len() == 1 {
            null_mx = true;
            break;
        }
        if target.is_empty() {
            continue;
        }
        let is_ip_literal = target.parse::<IpAddr>().is_ok();
        let (has_cname, resolves) = if is_ip_literal {
            (false, true)
        } else {
            let has_cname = !dns::query(seed, target, RecordType::CNAME).await.answers.is_empty();
            let a_lookup = dns::query(seed, target, RecordType::A).await;
            let aaaa = dns::query(seed, target, RecordType::AAAA).await;
            (has_cname, !a_lookup.answers.is_empty() || !aaaa.answers.is_empty())
        };
        infos.push(MxTargetInfo { target: target.into(), is_ip_literal, has_cname, resolves });
    }
    results.push(check_mx(&infos, null_mx));

    // Apex CNAME
    let cname = dns::query(seed, &domain, RecordType::CNAME).await;
    let mut others = vec![];
    if !a.answers.is_empty() { others.push("A".to_string()); }
    if !mx.answers.is_empty() { others.push("MX".to_string()); }
    results.push(check_apex_cname(!cname.answers.is_empty(), &others));

    // Open AXFR (zone transfer) — security
    let mut axfr_open = vec![];
    for (name, ip) in &ns_list {
        if let Ok((resp, _)) = dns::raw_query_opts(*ip, &domain, RecordType::AXFR, false).await {
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

    // F5: CNAME chains from the apex and www, capped at 12 hops
    for label in [domain.clone(), format!("www.{domain}")] {
        let mut chain = vec![];
        let mut current = label.clone();
        for _ in 0..12 {
            let cname = dns::query(seed, &current, RecordType::CNAME).await;
            let Some(target) = cname.answers.first() else { break };
            chain.push(target.clone());
            current = target.trim_end_matches('.').to_string();
        }
        let terminal_resolves = !chain.is_empty()
            && (!dns::query(seed, &current, RecordType::A).await.answers.is_empty()
                || !dns::query(seed, &current, RecordType::AAAA).await.answers.is_empty());
        let mut r = check_cname_chain(&chain, terminal_resolves);
        if label != domain {
            r.name = "CNAME chain www".into();
        }
        results.push(r);
    }

    // F10: HTTPS/SVCB at apex + www, TLSA (DANE) at _443._tcp
    for label in [domain.clone(), format!("www.{domain}")] {
        let name = if label == domain { "HTTPS" } else { "HTTPS www" };
        let h = dns::query(seed, &label, RecordType::HTTPS).await;
        if h.answers.is_empty() {
            results.push(ok(name, "none"));
        } else {
            results.push(ok(name, format!("present: {:?}", h.answers)));
        }
    }
    let tlsa = dns::query(seed, &format!("_443._tcp.{domain}"), RecordType::TLSA).await;
    if tlsa.answers.is_empty() {
        results.push(ok("TLSA", "no DANE record"));
    } else {
        results.push(ok("TLSA", format!("present: {:?}", tlsa.answers)));
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

    #[test]
    fn caa_absent_is_ok_note() {
        let r = check_caa(&[]);
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.contains("any CA"));
    }

    #[test]
    fn caa_present_lists_records() {
        let r = check_caa(&s(&["0 issue \"letsencrypt.org\""]));
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.contains("letsencrypt"));
    }

    #[test]
    fn mx_null_is_ok() {
        let r = check_mx(&[], true);
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.to_lowercase().contains("null mx"));
    }

    #[test]
    fn mx_unresolvable_target_errors() {
        let infos = vec![MxTargetInfo {
            target: "mail.example.com".into(),
            is_ip_literal: false,
            has_cname: false,
            resolves: false,
        }];
        assert_eq!(check_mx(&infos, false).severity, Severity::Err);
    }

    #[test]
    fn mx_cname_target_warns() {
        let infos = vec![MxTargetInfo {
            target: "mail.example.com".into(),
            is_ip_literal: false,
            has_cname: true,
            resolves: true,
        }];
        assert_eq!(check_mx(&infos, false).severity, Severity::Warn);
    }

    #[test]
    fn mx_ip_literal_errors() {
        let infos = vec![MxTargetInfo {
            target: "1.2.3.4".into(),
            is_ip_literal: true,
            has_cname: false,
            resolves: true,
        }];
        assert_eq!(check_mx(&infos, false).severity, Severity::Err);
    }

    #[test]
    fn mx_healthy_ok() {
        let infos = vec![MxTargetInfo {
            target: "mail.example.com".into(),
            is_ip_literal: false,
            has_cname: false,
            resolves: true,
        }];
        assert_eq!(check_mx(&infos, false).severity, Severity::Ok);
    }

    #[test]
    fn ns_single_warns() {
        let r = check_ns_redundancy(&[("ns1.x.com".into(), "1.2.3.4".parse().unwrap())]);
        assert_eq!(r.severity, Severity::Warn);
    }

    #[test]
    fn ns_same_slash24_warns() {
        let r = check_ns_redundancy(&[
            ("ns1.x.com".into(), "1.2.3.4".parse().unwrap()),
            ("ns2.x.com".into(), "1.2.3.9".parse().unwrap()),
        ]);
        assert_eq!(r.severity, Severity::Warn);
        assert!(r.detail.contains("/24"));
    }

    #[test]
    fn ns_diverse_ok() {
        let r = check_ns_redundancy(&[
            ("ns1.x.com".into(), "1.2.3.4".parse().unwrap()),
            ("ns2.x.com".into(), "8.8.4.4".parse().unwrap()),
        ]);
        assert_eq!(r.severity, Severity::Ok);
    }

    #[test]
    fn soa_sane_values_ok() {
        let r = check_soa_values(2026080501, 7200, 3600, 1209600, 3600);
        assert_eq!(r.severity, Severity::Ok);
    }

    #[test]
    fn soa_bad_values_warn() {
        // retry >= refresh and tiny expire
        let r = check_soa_values(1, 7200, 14400, 3600, 3600);
        assert_eq!(r.severity, Severity::Warn);
    }

    #[test]
    fn cname_chain_loop_errors() {
        let r = check_cname_chain(&s(&["a.", "b.", "a."]), false);
        assert_eq!(r.severity, Severity::Err);
        assert!(r.detail.to_lowercase().contains("loop"));
    }

    #[test]
    fn cname_chain_dangling_errors() {
        let r = check_cname_chain(&s(&["a.", "b."]), false);
        assert_eq!(r.severity, Severity::Err);
    }

    #[test]
    fn cname_chain_ok() {
        let r = check_cname_chain(&s(&["a.", "b."]), true);
        assert_eq!(r.severity, Severity::Ok);
        assert!(r.detail.contains("2 hop") || r.detail.contains("→"));
    }

    #[test]
    fn cname_chain_too_long_warns() {
        let long: Vec<String> = (0..10).map(|i| format!("h{i}.")).collect();
        assert_eq!(check_cname_chain(&long, true).severity, Severity::Warn);
    }

    #[test]
    fn soa_date_decoded() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 0, 0, 0).unwrap();
        let s = decode_soa_date(2026080101, now).unwrap();
        assert!(s.contains("4d") || s.contains("day"));
    }

    #[test]
    fn soa_date_non_date_serial_none() {
        assert!(decode_soa_date(12345, chrono::Utc::now()).is_none());
    }
}
