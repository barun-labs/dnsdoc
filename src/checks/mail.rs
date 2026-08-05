//! Mail tab: MX FCrDNS, MTA-STS, TLS-RPT, BIMI, DKIM key strength.

use std::net::IpAddr;

use hickory_proto::rr::{RData, RecordType};
use tokio::sync::mpsc;

use crate::checks::audit::DKIM_SELECTORS;
use crate::dns;
use crate::types::{CheckResult, Msg, Severity};

fn ok(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Ok, detail: detail.into() }
}
fn warn(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Warn, detail: detail.into() }
}

/// Estimate DKIM key strength from the base64 `p=` value without a base64
/// crate: ~3 bytes per 4 chars. Flag < 128 bytes (~1024-bit) as weak.
pub fn dkim_key_note(p_b64: &str, k: Option<&str>) -> String {
    if k == Some("ed25519") {
        return "ed25519 key".to_string();
    }
    // Approx decoded length without a base64 crate: 3 bytes per 4 chars.
    let bytes = p_b64.trim().len() * 3 / 4;
    if bytes < 128 {
        format!("~{bytes} bytes — weak (looks like 1024-bit or smaller)")
    } else {
        format!("~{bytes} bytes — ok")
    }
}

/// First `field=` value in a DKIM-style `;`-separated TXT record.
fn tag_value<'a>(rec: &'a str, tag: &str) -> Option<&'a str> {
    rec.split(';').map(|p| p.trim()).find_map(|p| p.strip_prefix(tag))
}

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let mut results = vec![];
    let seed: IpAddr = "8.8.8.8".parse().unwrap();

    // MX: per-host A/AAAA + PTR + FCrDNS verdict
    let mx = dns::query(seed, &domain, RecordType::MX).await;
    let hosts: Vec<String> = mx
        .answers
        .iter()
        .filter_map(|a| a.split_whitespace().last())
        .map(|t| t.trim_end_matches('.').to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if hosts.is_empty() {
        results.push(warn("MX", "no MX records (domain sends no mail, or none found)"));
    }
    for host in hosts {
        let a = dns::query(seed, &host, RecordType::A).await;
        let aaaa = dns::query(seed, &host, RecordType::AAAA).await;
        let mut sev = Severity::Ok;
        let mut detail = format!("{host} — ");
        if a.answers.is_empty() && aaaa.answers.is_empty() {
            detail.push_str("no A/AAAA");
            sev = Severity::Warn;
        } else {
            let ip_str = a.answers.first().cloned().unwrap_or_default();
            detail.push_str(&format!("{ip_str} — "));
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => {
                    // FCrDNS: PTR of the first A must resolve back to that IP
                    let ptr = match dns::raw_query(seed, &dns::reverse_name(ip), RecordType::PTR).await {
                        Ok((resp, _)) => resp
                            .answers()
                            .iter()
                            .filter(|r| r.record_type() == RecordType::PTR)
                            .filter_map(|r| r.data().try_into().ok().map(|d: &RData| d.to_string()))
                            .collect::<Vec<_>>(),
                        Err(_) => vec![],
                    };
                    match ptr.first() {
                        Some(ptrname) => {
                            let ptrname = ptrname.trim_end_matches('.');
                            let fwd = dns::query(seed, ptrname, RecordType::A).await;
                            if fwd.answers.iter().any(|x| x == &ip_str) {
                                detail.push_str(&format!("ptr {ptrname} — FCrDNS ✓"));
                            } else {
                                detail.push_str(&format!("ptr {ptrname} — FCrDNS ✗"));
                                sev = Severity::Warn;
                            }
                        }
                        None => {
                            detail.push_str("ptr (none) — FCrDNS ✗");
                            sev = Severity::Warn;
                        }
                    }
                }
                Err(_) => detail.push_str("no IPv4 — FCrDNS not checked"),
            }
        }
        results.push(CheckResult { name: "MX host".into(), severity: sev, detail });
    }

    // MTA-STS: TXT at _mta-sts.<domain>
    let mta_sts = dns::query(seed, &format!("_mta-sts.{domain}"), RecordType::TXT).await;
    if let Some(rec) = mta_sts.answers.first() {
        let id = tag_value(rec, "id=").unwrap_or("?");
        results.push(ok(
            "MTA-STS",
            format!("present (id {id}) — policy body not fetched (HTTPS out of scope)"),
        ));
    } else {
        results.push(warn("MTA-STS", "no _mta-sts TXT — MTA-STS not deployed"));
    }

    // TLS-RPT: TXT at _smtp._tls.<domain>
    let tls_rpt = dns::query(seed, &format!("_smtp._tls.{domain}"), RecordType::TXT).await;
    if let Some(rec) = tls_rpt.answers.first() {
        let rua = tag_value(rec, "rua=").unwrap_or("(no rua=)");
        results.push(ok("TLS-RPT", format!("present ({rua})")));
    } else {
        results.push(ok("TLS-RPT", "none — no TLS reporting configured (informational)"));
    }

    // BIMI: TXT at default._bimi.<domain>
    let bimi = dns::query(seed, &format!("default._bimi.{domain}"), RecordType::TXT).await;
    if let Some(rec) = bimi.answers.first() {
        let l = tag_value(rec, "l=").unwrap_or("(no l=)");
        results.push(ok("BIMI", format!("present ({l})")));
    } else {
        results.push(ok("BIMI", "none — no brand indicator (informational)"));
    }

    // DKIM: probe the shared selector list, rate the published key
    for sel in DKIM_SELECTORS {
        let q = dns::query(seed, &format!("{sel}._domainkey.{domain}"), RecordType::TXT).await;
        if let Some(rec) = q.answers.iter().find(|a| a.to_lowercase().contains("v=dkim1") || a.contains("p=")) {
            let p = tag_value(rec, "p=").unwrap_or("");
            let k = tag_value(rec, "k=");
            let note = dkim_key_note(p, k);
            let sev = if note.contains("weak") { Severity::Warn } else { Severity::Ok };
            results.push(CheckResult { name: format!("DKIM {sel}"), severity: sev, detail: note });
        }
    }

    let _ = tx.send(Msg::Mail(results)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkim_ed25519_noted() {
        let n = dkim_key_note("AAAA", Some("ed25519"));
        assert!(n.to_lowercase().contains("ed25519"));
    }
    #[test]
    fn dkim_short_rsa_flagged_weak() {
        // 128 bytes base64 ~ 172 chars; use a short key to trigger weak
        let short = "A".repeat(100); // decodes to 75 bytes < 128
        let n = dkim_key_note(&short, None);
        assert!(n.to_lowercase().contains("weak") || n.contains("1024"));
    }
    #[test]
    fn dkim_strong_rsa_ok() {
        let long = "A".repeat(400); // decodes ~300 bytes ~ 2048-bit
        let n = dkim_key_note(&long, None);
        assert!(!n.to_lowercase().contains("weak"));
    }
}
