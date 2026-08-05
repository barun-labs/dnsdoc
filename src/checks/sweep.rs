//! Sweep tab: probe a fixed candidate list of common names for leftover
//! records. Streams one Msg per hit so rows appear as the sweep progresses.

use hickory_proto::rr::{RData, RecordType};
use tokio::sync::mpsc;

use crate::dns;
use crate::types::{Msg, SweepRow};

const CANDIDATES: &[&str] = &["www","mail","smtp","imap","webmail","api","app","dev","staging","test","vpn","remote","autodiscover","autoconfig","mta-sts","_acme-challenge","ns1","ns2","cdn","shop","blog","docs","status","git"];

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let seed: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    let _ = tx.send(Msg::SweepStart).await;
    // Sequential is fine: 24 names, each ~tens of ms.
    for c in CANDIDATES {
        let name = format!("{c}.{domain}");
        let Ok((resp, _)) = dns::raw_query(seed, &name, RecordType::A).await else {
            continue;
        };
        let a_answers: Vec<String> = resp
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::A)
            .filter_map(|r| r.data().try_into().ok().map(|d: &RData| dns::rdata_to_string(d)))
            .collect();
        if a_answers.is_empty() {
            continue; // miss — hits only, keeps the list tight
        }
        let _ = tx
            .send(Msg::SweepRow(SweepRow {
                name: name.clone(),
                rtype: "A".into(),
                answers: a_answers,
            }))
            .await;
        // Follow CNAME targets so aliased hosts show where they point.
        if let Ok((cresp, _)) = dns::raw_query(seed, &name, RecordType::CNAME).await {
            let c_answers: Vec<String> = cresp
                .answers()
                .iter()
                .filter(|r| r.record_type() == RecordType::CNAME)
                .filter_map(|r| r.data().try_into().ok().map(|d: &RData| dns::rdata_to_string(d)))
                .collect();
            if !c_answers.is_empty() {
                let _ = tx
                    .send(Msg::SweepRow(SweepRow {
                        name,
                        rtype: "CNAME".into(),
                        answers: c_answers,
                    }))
                    .await;
            }
        }
    }
}
