use futures::future::join_all;
use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;

use crate::config::Resolver;
use crate::dns;
use crate::types::{Msg, PropagationRow};

pub async fn run(
    domain: String,
    rtype: RecordType,
    resolvers: Vec<Resolver>,
    tx: mpsc::Sender<Msg>,
) {
    let _ = tx.send(Msg::PropStart(resolvers.len())).await;
    let ns = dns::authoritative_ns(&domain).await.ok();
    let auth = match &ns {
        Some(ns) => {
            let display: Vec<String> =
                ns.iter().map(|(name, ip)| format!("{name} ({ip})")).collect();
            let _ = tx.send(Msg::AuthNs(display)).await;
            dns::answer_from_ns(ns, &domain, rtype).await.ok()
        }
        None => None,
    };
    if let Some(a) = &auth {
        let _ = tx.send(Msg::AuthAnswer(a.clone())).await;
    }

    let futs = resolvers.into_iter().map(|r| {
        let domain = domain.clone();
        let auth = auth.clone();
        let tx = tx.clone();
        async move {
            let out = dns::query(r.ip, &domain, rtype).await;
            let mut row = PropagationRow {
                resolver: r.name,
                ip: r.ip,
                answers: out.answers,
                ttl: out.ttl,
                latency_ms: if out.error.is_none() {
                    Some(out.latency_ms)
                } else {
                    None
                },
                error: out.error,
                matches_auth: None,
            };
            row.matches_auth = mark_match(&row, auth.as_deref());
            let _ = tx.send(Msg::PropRow(row.clone())).await;
            row
        }
    });
    let rows: Vec<PropagationRow> = join_all(futs).await;
    let _ = tx.send(Msg::Propagation(rows)).await; // final ordered set, unchanged
}

fn mark_match(row: &PropagationRow, auth: Option<&[String]>) -> Option<bool> {
    match (auth, &row.error) {
        (Some(auth), None) => {
            let mut a = auth.to_vec();
            a.sort();
            Some(a == row.answers)
        }
        _ => None,
    }
}

/// (rows agreeing with authoritative, rows that answered without error)
pub fn consensus(rows: &[PropagationRow]) -> (usize, usize) {
    let answered = rows.iter().filter(|r| r.error.is_none()).count();
    let agree = rows.iter().filter(|r| r.matches_auth == Some(true)).count();
    (agree, answered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn row(answers: &[&str], error: Option<&str>, matches: Option<bool>) -> PropagationRow {
        PropagationRow {
            resolver: "t".into(),
            ip: "1.1.1.1".parse::<IpAddr>().unwrap(),
            answers: answers.iter().map(|s| s.to_string()).collect(),
            ttl: Some(300),
            latency_ms: Some(10),
            error: error.map(|s| s.to_string()),
            matches_auth: matches,
        }
    }

    #[test]
    fn consensus_counts_agree_and_answered() {
        let rows = vec![
            row(&["1.2.3.4"], None, Some(true)),
            row(&["5.6.7.8"], None, Some(false)),
            row(&[], Some("timeout"), None),
        ];
        assert_eq!(consensus(&rows), (1, 2));
    }

    #[test]
    fn match_ignores_answer_order() {
        let r = row(&["1.1.1.1", "2.2.2.2"], None, None);
        let auth = vec!["2.2.2.2".to_string(), "1.1.1.1".to_string()];
        assert_eq!(mark_match(&r, Some(&auth)), Some(true));
    }

    #[test]
    fn errored_row_never_matches() {
        let r = row(&[], Some("timeout"), None);
        assert_eq!(mark_match(&r, Some(&["1.2.3.4".to_string()])), None);
    }
}
