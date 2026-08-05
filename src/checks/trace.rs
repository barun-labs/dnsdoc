use std::net::IpAddr;

use hickory_proto::rr::{RData, RecordType};
use tokio::sync::mpsc;

use crate::dns;
use crate::types::{Msg, TraceHop};

// A couple of root servers; iterative resolution starts here.
const ROOTS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("f.root-servers.net", "192.5.5.241"),
    ("k.root-servers.net", "193.0.14.129"),
];

/// Progressive zone cuts for a domain, root-first.
/// "example.com" -> [".", "com.", "example.com."]
pub fn next_labels(domain: &str) -> Vec<String> {
    let d = domain.trim_end_matches('.');
    let parts: Vec<&str> = d.split('.').collect();
    let mut zones = vec![".".to_string()];
    for i in (0..parts.len()).rev() {
        zones.push(format!("{}.", parts[i..].join(".")));
    }
    zones
}

async fn dnssec_note(server: IpAddr, zone: &str) -> String {
    if zone == "." {
        return "root (trust anchor)".to_string();
    }
    let ds = dns::query(server, zone.trim_end_matches('.'), RecordType::DS).await;
    let dnskey = dns::query(server, zone.trim_end_matches('.'), RecordType::DNSKEY).await;
    match (ds.answers.is_empty(), dnskey.answers.is_empty()) {
        (true, _) => "unsigned zone (no DS)".to_string(),
        (false, false) => "signed (DS + DNSKEY present)".to_string(),
        (false, true) => "BROKEN: DS present but no DNSKEY".to_string(),
    }
}

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let zones = next_labels(&domain);
    // Current set of servers to ask, start at roots.
    let mut servers: Vec<(String, IpAddr)> = ROOTS
        .iter()
        .map(|(n, ip)| (n.to_string(), ip.parse().unwrap()))
        .collect();

    let mut hops = vec![];
    // For each zone cut below root, ask the current servers who serves it.
    for zone in zones.iter().skip(1) {
        let (server_name, server_ip) = servers[0].clone();
        let mut hop = TraceHop {
            zone: zone.clone(),
            server: format!("{server_name} ({server_ip})"),
            latency_ms: None,
            note: None,
            dnssec: None,
            error: None,
        };

        match dns::raw_query(server_ip, zone.trim_end_matches('.'), RecordType::NS).await {
            Ok((resp, latency)) => {
                hop.latency_ms = Some(latency);
                // Referral NS come from answer or authority section.
                let ns_names: Vec<String> = resp
                    .answers()
                    .iter()
                    .chain(resp.name_servers().iter())
                    .filter(|r| r.record_type() == RecordType::NS)
                    .filter_map(|r| r.data().try_into().ok().map(|d: &RData| dns::rdata_to_string(d)))
                    .collect();

                if ns_names.is_empty() {
                    if resp.header().authoritative() {
                        hop.note = Some("authoritative, no further referral".into());
                    } else {
                        hop.note = Some("LAME: no AA flag and no referral".into());
                    }
                } else {
                    // Resolve next-hop server IPs from glue (additional) or lookup.
                    let mut next: Vec<(String, IpAddr)> = vec![];
                    for r in resp.additionals() {
                        if let Ok(&RData::A(a)) = r.data().try_into() {
                            next.push((r.name().to_string(), IpAddr::V4(a.0)));
                        }
                    }
                    if next.is_empty() {
                        // No glue: resolve first NS name via public resolver.
                        let seed: IpAddr = "8.8.8.8".parse().unwrap();
                        for ns in &ns_names {
                            let a = dns::query(seed, ns.trim_end_matches('.'), RecordType::A).await;
                            if let Some(ip) = a.answers.first().and_then(|s| s.parse().ok()) {
                                next.push((ns.clone(), ip));
                            }
                            if !next.is_empty() {
                                break;
                            }
                        }
                    }
                    hop.note = Some(format!("delegated to {} NS", ns_names.len()));
                    if !next.is_empty() {
                        servers = next;
                    }
                }
                hop.dnssec = Some(dnssec_note(server_ip, zone).await);
            }
            Err(e) => {
                hop.error = Some(e.to_string());
            }
        }

        let _ = tx.send(Msg::TraceHopArrived(hop.clone())).await;
        hops.push(hop);
    }

    let _ = tx.send(Msg::Trace(hops)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_labels_basic() {
        assert_eq!(next_labels("example.com"), vec![".", "com.", "example.com."]);
    }

    #[test]
    fn next_labels_subdomain() {
        assert_eq!(
            next_labels("a.b.example.com"),
            vec![".", "com.", "example.com.", "b.example.com.", "a.b.example.com."]
        );
    }

    #[test]
    fn next_labels_trailing_dot_ignored() {
        assert_eq!(next_labels("example.com."), vec![".", "com.", "example.com."]);
    }
}
