use std::collections::HashMap;
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

/// Pair each referral NS name with its glue IP when known.
pub fn format_referral(ns_names: &[String], glue: &HashMap<String, IpAddr>) -> Vec<String> {
    ns_names
        .iter()
        .map(|n| match glue.get(n) {
            Some(ip) => format!("{n} ({ip})"),
            None => n.clone(),
        })
        .collect()
}

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
            ns: vec![],
            dnssec: None,
            error: None,
        };

        // RD=0: ask the server for its own delegation data, no recursion.
        match dns::raw_query_opts(server_ip, zone.trim_end_matches('.'), RecordType::NS, false).await {
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
                    // Glue: pair every additional A record with its owner name.
                    let mut glue: HashMap<String, IpAddr> = HashMap::new();
                    for r in resp.additionals() {
                        if let Ok(&RData::A(a)) = r.data().try_into() {
                            glue.insert(r.name().to_string(), IpAddr::V4(a.0));
                        }
                    }
                    hop.ns = format_referral(&ns_names, &glue);

                    // Resolve next-hop server IPs from glue (additional) or lookup.
                    let mut next: Vec<(String, IpAddr)> = ns_names
                        .iter()
                        .filter_map(|n| glue.get(n).map(|ip| (n.clone(), *ip)))
                        .collect();
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

    #[test]
    fn format_referral_pairs_glue() {
        let ns_names = vec!["ns01.x.com.".to_string(), "ns02.x.com.".to_string()];
        let mut glue = std::collections::HashMap::new();
        glue.insert("ns01.x.com.".to_string(), "64.96.1.1".parse::<std::net::IpAddr>().unwrap());
        let out = format_referral(&ns_names, &glue);
        assert_eq!(out, vec!["ns01.x.com. (64.96.1.1)".to_string(), "ns02.x.com.".to_string()]);
    }
}
