use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use hickory_client::client::Client;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::xfer::DnsHandle;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::tcp::TcpClientStream;
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
        RData::PTR(p) => p.to_string(),
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
    raw_query_opts(server, domain, rtype, true).await
}

/// Raw query with explicit recursion-desired control. `rd = false` is the
/// authoritative-server mode: the server must answer from its own zone data
/// and must not recurse on our behalf.
pub async fn raw_query_opts(
    server: IpAddr,
    domain: &str,
    rtype: RecordType,
    rd: bool,
) -> Result<(DnsResponse, u128)> {
    use futures::StreamExt;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    let name = Name::from_ascii(format!("{domain}."))?;
    let start = Instant::now();
    let resp = tokio::time::timeout(QUERY_TIMEOUT, async {
        let client = connect(server).await?;
        let mut msg = Message::new();
        msg.add_query(Query::query(name, rtype))
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(rd);
        client
            .send(msg)
            .next()
            .await
            .ok_or_else(|| anyhow!("no response"))?
            .map_err(|e| anyhow!(e))
    })
    .await
    .map_err(|_| anyhow!("timeout"))??;
    Ok((resp, start.elapsed().as_millis()))
}

/// Same as `raw_query_opts` but over TCP, for servers that truncate or
/// refuse UDP or where payload size matters.
pub async fn raw_query_tcp(
    server: IpAddr,
    domain: &str,
    rtype: RecordType,
    rd: bool,
) -> Result<(DnsResponse, u128)> {
    use futures::StreamExt;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    let name = Name::from_ascii(format!("{domain}."))?;
    let start = Instant::now();
    let resp = tokio::time::timeout(QUERY_TIMEOUT, async {
        let addr = SocketAddr::new(server, 53);
        let (stream, sender) =
            TcpClientStream::new(addr, None, Some(QUERY_TIMEOUT), TokioRuntimeProvider::new());
        let (client, bg) = Client::new(stream, sender, None).await?;
        tokio::spawn(bg);
        let mut msg = Message::new();
        msg.add_query(Query::query(name, rtype))
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(rd);
        client
            .send(msg)
            .next()
            .await
            .ok_or_else(|| anyhow!("no response"))?
            .map_err(|e| anyhow!(e))
    })
    .await
    .map_err(|_| anyhow!("timeout"))??;
    Ok((resp, start.elapsed().as_millis()))
}

/// UDP query carrying an EDNS OPT record with a settable DNSSEC-OK bit.
/// `do_bit = true` asks the server to include RRSIGs in answers.
pub async fn raw_query_edns(
    server: IpAddr,
    domain: &str,
    rtype: RecordType,
    rd: bool,
    do_bit: bool,
) -> Result<(DnsResponse, u128)> {
    use futures::StreamExt;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    let name = Name::from_ascii(format!("{domain}."))?;
    let start = Instant::now();
    let resp = tokio::time::timeout(QUERY_TIMEOUT, async {
        let client = connect(server).await?;
        let mut msg = Message::new();
        msg.add_query(Query::query(name, rtype))
            .set_id(rand::random())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(rd);
        {
            let edns = msg.extensions_mut().get_or_insert_with(Default::default);
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(do_bit);
        }
        client
            .send(msg)
            .next()
            .await
            .ok_or_else(|| anyhow!("no response"))?
            .map_err(|e| anyhow!(e))
    })
    .await
    .map_err(|_| anyhow!("timeout"))??;
    Ok((resp, start.elapsed().as_millis()))
}

/// Reverse-lookup name for an IP: in-addr.arpa for v4, nibble form for v6.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for octet in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", octet & 0xf, octet >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

pub async fn query(server: IpAddr, domain: &str, rtype: RecordType) -> QueryOutcome {
    let start = Instant::now();
    match raw_query(server, domain, rtype).await {
        Ok((resp, latency_ms)) => {
            // Non-NoError rcodes are answers too — surface them as errors so
            // "no answers" never masquerades as a silent empty reply.
            let rcode = resp.response_code();
            if rcode != hickory_proto::op::ResponseCode::NoError {
                let code = match rcode {
                    hickory_proto::op::ResponseCode::Refused => "REFUSED".to_string(),
                    hickory_proto::op::ResponseCode::ServFail => "SERVFAIL".to_string(),
                    hickory_proto::op::ResponseCode::NXDomain => "NXDOMAIN".to_string(),
                    hickory_proto::op::ResponseCode::NotImp => "NOTIMP".to_string(),
                    hickory_proto::op::ResponseCode::FormErr => "FORMERR".to_string(),
                    other => other.to_string().to_uppercase(),
                };
                return QueryOutcome {
                    answers: vec![],
                    ttl: None,
                    latency_ms,
                    error: Some(code),
                };
            }
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
    answer_from_ns(&ns, domain, rtype).await
}

/// Same, but reuses an already-fetched NS set.
pub async fn answer_from_ns(
    ns: &[(String, IpAddr)],
    domain: &str,
    rtype: RecordType,
) -> Result<Vec<String>> {
    for (_, ip) in ns {
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

    #[test]
    fn reverse_name_v4() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(reverse_name(ip), "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn reverse_name_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let n = reverse_name(ip);
        assert!(n.ends_with("ip6.arpa"));
        // 32 nibbles + ip6 + arpa = 34 labels
        assert_eq!(n.matches('.').count(), 33);
    }
}
