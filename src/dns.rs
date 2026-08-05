use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::DnsResponse;

pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct QueryOutcome {
    pub answers: Vec<String>,
    pub ttl: Option<u32>,
    pub latency_ms: u128,
    pub error: Option<String>,
}

pub fn rdata_to_string(rdata: &RData) -> String {
    match rdata {
        RData::A(a) => a.to_string(),
        RData::AAAA(a) => a.to_string(),
        RData::CNAME(c) => c.to_string(),
        RData::NS(ns) => ns.to_string(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::TXT(txt) => txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join(""),
        RData::SOA(soa) => format!(
            "{} {} serial={}",
            soa.mname(),
            soa.rname(),
            soa.serial()
        ),
        other => other.to_string(),
    }
}

async fn connect(server: IpAddr) -> Result<Client> {
    let addr = SocketAddr::new(server, 53);
    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new())
        .with_timeout(Some(QUERY_TIMEOUT))
        .build();
    let (client, bg) = Client::connect(stream).await?;
    tokio::spawn(bg);
    Ok(client)
}

/// Raw query against a specific server. Returns the full response so callers
/// can inspect flags (AA) and authority/additional sections.
pub async fn raw_query(
    server: IpAddr,
    domain: &str,
    rtype: RecordType,
) -> Result<(DnsResponse, u128)> {
    let name = Name::from_ascii(format!("{domain}."))?;
    let start = Instant::now();
    let resp = tokio::time::timeout(QUERY_TIMEOUT, async {
        let mut client = connect(server).await?;
        client
            .query(name, DNSClass::IN, rtype)
            .await
            .map_err(|e| anyhow!(e))
    })
    .await
    .map_err(|_| anyhow!("timeout"))??;
    Ok((resp, start.elapsed().as_millis()))
}

pub async fn query(server: IpAddr, domain: &str, rtype: RecordType) -> QueryOutcome {
    let start = Instant::now();
    match raw_query(server, domain, rtype).await {
        Ok((resp, latency_ms)) => {
            let mut answers: Vec<String> = resp
                .answers()
                .iter()
                .filter(|r| r.record_type() == rtype || r.record_type() == RecordType::CNAME)
                .filter_map(|r| r.data().try_into().ok().map(|d: &RData| rdata_to_string(d)))
                .collect();
            answers.sort();
            let ttl = resp.answers().iter().map(|r| r.ttl()).min();
            QueryOutcome {
                answers,
                ttl,
                latency_ms,
                error: None,
            }
        }
        Err(e) => QueryOutcome {
            answers: vec![],
            ttl: None,
            latency_ms: start.elapsed().as_millis(),
            error: Some(e.to_string()),
        },
    }
}

/// Discover the domain's authoritative NS set (names + a resolved IPv4 each),
/// using a public resolver for the NS lookup and A lookups.
pub async fn authoritative_ns(domain: &str) -> Result<Vec<(String, IpAddr)>> {
    let seed: IpAddr = "8.8.8.8".parse().unwrap();
    // NS records may live at a parent zone when `domain` is a subdomain —
    // walk up until an NS set is found.
    let mut zone = domain.to_string();
    let ns_names: Vec<String> = loop {
        let out = query(seed, &zone, RecordType::NS).await;
        let names: Vec<String> = out
            .answers
            .iter()
            .filter(|a| a.ends_with('.'))
            .cloned()
            .collect();
        if !names.is_empty() {
            break names;
        }
        match zone.split_once('.') {
            Some((_, rest)) if rest.contains('.') => zone = rest.to_string(),
            _ => return Err(anyhow!("no NS records found for {domain}")),
        }
    };
    let mut out = vec![];
    for ns in &ns_names {
        let a = query(seed, ns.trim_end_matches('.'), RecordType::A).await;
        if let Some(ip_str) = a.answers.first() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                out.push((ns.clone(), ip));
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!("could not resolve any NS address for {domain}"));
    }
    Ok(out)
}

/// Answer for `domain`/`rtype` straight from the first reachable authoritative NS.
pub async fn authoritative_answer(domain: &str, rtype: RecordType) -> Result<Vec<String>> {
    let ns = authoritative_ns(domain).await?;
    for (_, ip) in &ns {
        let out = query(*ip, domain, rtype).await;
        if out.error.is_none() {
            return Ok(out.answers);
        }
    }
    Err(anyhow!("no authoritative server answered for {domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, MX, TXT};
    use std::net::Ipv4Addr;

    #[test]
    fn renders_a_record() {
        let r = RData::A(A(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(rdata_to_string(&r), "1.2.3.4");
    }

    #[test]
    fn renders_mx_record() {
        let r = RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap()));
        assert_eq!(rdata_to_string(&r), "10 mail.example.com.");
    }

    #[test]
    fn renders_txt_record_joined() {
        let r = RData::TXT(TXT::new(vec!["v=spf1 ".to_string(), "-all".to_string()]));
        assert_eq!(rdata_to_string(&r), "v=spf1 -all");
    }
}
