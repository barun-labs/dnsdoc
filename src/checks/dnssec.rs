//! DNSSEC tab: RRSIG expiry watch, resolver validation matrix, DS/DNSKEY chain.
//!
//! Collectors do network via `dns::raw_query_edns` (DO bit) against the
//! authoritative NS (RRSIG) or a validating public resolver (chain); pure
//! helpers carry the reasoning and are unit-tested without network.

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::Algorithm;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use tokio::sync::mpsc;

use crate::checks::trace;
use crate::config::Resolver;
use crate::dns;
use crate::types::{CheckResult, Msg, Severity};

/// Validating public resolver used for DS/DNSKEY chain lookups.
const VALIDATOR: &str = "1.1.1.1";

fn warn(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Warn, detail: detail.into() }
}
fn err(name: &str, detail: impl Into<String>) -> CheckResult {
    CheckResult { name: name.into(), severity: Severity::Err, detail: detail.into() }
}

/// IANA DNSSEC algorithm number -> display name.
pub fn algo_name(n: u8) -> &'static str {
    match n {
        1 => "RSAMD5",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "unknown",
    }
}

/// True for algorithms whose hash is broken (RFC 6944 / RFC 8624).
pub fn algo_deprecated(n: u8) -> bool {
    matches!(n, 1 | 3 | 5 | 6 | 7)
}

/// Severity + countdown for a signature expiry: Err when expired,
/// Warn under a week, else Ok. `now` is injected for tests.
pub fn rrsig_severity(expiry_unix: i64, now_unix: i64) -> (Severity, String) {
    let secs = expiry_unix - now_unix;
    if secs <= 0 {
        (Severity::Err, format!("EXPIRED {}d ago", (-secs) / 86400))
    } else if secs < 7 * 86400 {
        (Severity::Warn, format!("expires in {}d", secs / 86400))
    } else {
        (Severity::Ok, format!("expires in {}d", secs / 86400))
    }
}

/// Mirror of `Algorithm::from_u8` — hickory exposes no `to_u8`.
#[allow(deprecated)] // RSAMD5/DSA/RSASHA1 variants are marked deprecated
fn algo_num(a: Algorithm) -> u8 {
    match a {
        Algorithm::RSAMD5 => 1,
        Algorithm::DSA => 3,
        Algorithm::RSASHA1 => 5,
        Algorithm::RSASHA1NSEC3SHA1 => 7,
        Algorithm::RSASHA256 => 8,
        Algorithm::RSASHA512 => 10,
        Algorithm::ECDSAP256SHA256 => 13,
        Algorithm::ECDSAP384SHA384 => 14,
        Algorithm::ED25519 => 15,
        Algorithm::Unknown(n) => n,
        // non-exhaustive enum — future algorithm variants land here
        _ => 0,
    }
}

fn typed_rrsigs(resp: &hickory_proto::xfer::DnsResponse) -> Vec<&hickory_proto::dnssec::rdata::RRSIG> {
    resp.answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig),
            _ => None,
        })
        .collect()
}

pub async fn run(domain: String, resolvers: Vec<Resolver>, tx: mpsc::Sender<Msg>) {
    let mut results: Vec<CheckResult> = Vec::new();
    let now = chrono::Utc::now().timestamp();

    // 1. RRSIG expiry (F1) — signatures straight from the zone, RD=0 + DO=1.
    let ns_ip = dns::authoritative_ns(&domain).await.ok().and_then(|ns| ns.first().map(|(_, ip)| *ip));
    let mut any_rrsig = false;
    if let Some(ip) = ns_ip {
        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::DNSKEY,
        ] {
            if let Ok((resp, _)) = dns::raw_query_edns(ip, &domain, rtype, false, true).await {
                for sig in typed_rrsigs(&resp) {
                    any_rrsig = true;
                    let (sev, msg) = rrsig_severity(sig.sig_expiration().get() as i64, now);
                    results.push(CheckResult {
                        name: format!("RRSIG {rtype}"),
                        severity: sev,
                        detail: format!(
                            "{} keytag {} — {}",
                            algo_name(algo_num(sig.algorithm())),
                            sig.key_tag(),
                            msg
                        ),
                    });
                }
            }
        }
    }
    if !any_rrsig {
        results.push(warn("RRSIG", "zone appears unsigned (no RRSIG returned with DO=1)"));
    }

    // 2. Validation matrix (F2) — AD flag per resolver, DO=1.
    let mut ad_count = 0usize;
    for r in &resolvers {
        match dns::raw_query_edns(r.ip, &domain, RecordType::A, true, true).await {
            Ok((resp, ms)) => {
                let rcode = resp.response_code();
                let ad = resp.header().authentic_data();
                if ad {
                    ad_count += 1;
                }
                let sev = if rcode != ResponseCode::NoError {
                    Severity::Err
                } else if ad {
                    Severity::Ok
                } else {
                    Severity::Warn
                };
                results.push(CheckResult {
                    name: format!("validate {}", r.name),
                    severity: sev,
                    detail: format!("AD {} · {} · {}ms", if ad { "✓" } else { "✗" }, rcode, ms),
                });
            }
            Err(e) => results.push(err(&format!("validate {}", r.name), format!("query failed: {e}"))),
        }
    }
    if !resolvers.is_empty() {
        results.insert(
            0,
            CheckResult {
                name: "DNSSEC validation".into(),
                severity: if ad_count == resolvers.len() { Severity::Ok } else { Severity::Warn },
                detail: format!("{ad_count} of {} resolvers set AD", resolvers.len()),
            },
        );
    }

    // 3. Chain detail (F6) — DS at the parent vs DNSKEY at the zone, per cut.
    if let Ok(validator) = VALIDATOR.parse::<std::net::IpAddr>() {
        for zone in trace::next_labels(&domain).iter().skip(1) {
            let z = zone.trim_end_matches('.');
            let mut ds_tags: Vec<u16> = Vec::new();
            let mut ds_algos: Vec<u8> = Vec::new();
            if let Ok((resp, _)) = dns::raw_query_edns(validator, z, RecordType::DS, true, true).await {
                for r in resp.answers() {
                    if let RData::DNSSEC(DNSSECRData::DS(ds)) = r.data() {
                        ds_tags.push(ds.key_tag());
                        ds_algos.push(algo_num(ds.algorithm()));
                    }
                }
            }
            let mut dnskey_tags: Vec<u16> = Vec::new();
            if let Ok((resp, _)) = dns::raw_query_edns(validator, z, RecordType::DNSKEY, true, true).await {
                for r in resp.answers() {
                    if let RData::DNSSEC(DNSSECRData::DNSKEY(k)) = r.data() {
                        if let Ok(t) = k.calculate_key_tag() {
                            dnskey_tags.push(t);
                        }
                    }
                }
            }
            let missing: Vec<String> = ds_tags
                .iter()
                .filter(|t| !dnskey_tags.contains(t))
                .map(|t| format!("keytag {t}"))
                .collect();
            let (sev, detail) = if ds_tags.is_empty() {
                (Severity::Ok, "no DS at parent (insecure delegation)".to_string())
            } else if !missing.is_empty() {
                (
                    Severity::Err,
                    format!("DS {} has no matching DNSKEY", missing.join(", ")),
                )
            } else if ds_algos.iter().any(|n| algo_deprecated(*n)) {
                (
                    Severity::Warn,
                    format!(
                        "{} → matches DNSKEY, but deprecated algorithm",
                        ds_algos.iter().map(|n| algo_name(*n)).collect::<Vec<_>>().join(", ")
                    ),
                )
            } else {
                (
                    Severity::Ok,
                    format!(
                        "{} → {} DNSKEY tags match",
                        ds_algos.iter().map(|n| algo_name(*n)).collect::<Vec<_>>().join(", "),
                        dnskey_tags.len()
                    ),
                )
            };
            results.push(CheckResult { name: format!("chain {zone}"), severity: sev, detail });
        }
    }

    let _ = tx.send(Msg::Dnssec(results)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrsig_expired_is_err() {
        let (sev, msg) = rrsig_severity(1000, 2000);
        assert_eq!(sev, Severity::Err);
        assert!(msg.to_lowercase().contains("expired"));
    }

    #[test]
    fn rrsig_expiring_soon_warns() {
        let now = 1_000_000;
        let (sev, _) = rrsig_severity(now + 3 * 86400, now); // 3 days
        assert_eq!(sev, Severity::Warn);
    }

    #[test]
    fn rrsig_healthy_ok() {
        let now = 1_000_000;
        let (sev, msg) = rrsig_severity(now + 20 * 86400, now);
        assert_eq!(sev, Severity::Ok);
        assert!(msg.contains("20d") || msg.contains("expires"));
    }

    #[test]
    fn algo_names_and_deprecation() {
        assert_eq!(algo_name(13), "ECDSAP256SHA256");
        assert!(algo_deprecated(5)); // RSASHA1
        assert!(algo_deprecated(7));
        assert!(!algo_deprecated(13));
    }
}
