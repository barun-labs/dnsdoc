use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;

use crate::dns;
use crate::types::{MonitorEvent, Msg};

/// True when the record's answer set changed (order-insensitive).
pub fn diff(old: &[String], new: &[String]) -> bool {
    let mut a = old.to_vec();
    let mut b = new.to_vec();
    a.sort();
    b.sort();
    a != b
}

pub fn load_history(path: &Path) -> Vec<MonitorEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

pub fn append_history(path: &Path, ev: &MonitorEvent) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        if let Ok(line) = serde_json::to_string(ev) {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub async fn run(
    domain: String,
    rtypes: Vec<RecordType>,
    interval: Duration,
    history_path: PathBuf,
    tx: mpsc::Sender<Msg>,
) {
    let seed: IpAddr = "8.8.8.8".parse().unwrap();
    let mut last: HashMap<String, Vec<String>> = HashMap::new();

    loop {
        for rtype in &rtypes {
            let out = dns::query(seed, &domain, *rtype).await;
            let key = format!("{rtype:?}");
            let _ = tx
                .send(Msg::MonitorSnapshot {
                    rtype: key.clone(),
                    answers: out.answers.clone(),
                    ttl: out.ttl,
                })
                .await;

            if let Some(prev) = last.get(&key) {
                if diff(prev, &out.answers) {
                    let ev = MonitorEvent {
                        timestamp: now_iso(),
                        rtype: key.clone(),
                        old: prev.clone(),
                        new: out.answers.clone(),
                    };
                    append_history(&history_path, &ev);
                    let _ = tx.send(Msg::Monitor(ev)).await;
                }
            }
            last.insert(key, out.answers);
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_ignores_order() {
        assert!(!diff(&["a".into(), "b".into()], &["b".into(), "a".into()]));
    }

    #[test]
    fn diff_detects_change() {
        assert!(diff(&["a".into()], &["a".into(), "b".into()]));
    }

    #[test]
    fn history_roundtrip() {
        let dir = std::env::temp_dir().join(format!("dnstest-{}", std::process::id()));
        let path = dir.join("h.jsonl");
        let _ = std::fs::remove_file(&path);
        let ev = MonitorEvent {
            timestamp: "2026-08-05T00:00:00Z".into(),
            rtype: "A".into(),
            old: vec!["1.1.1.1".into()],
            new: vec!["2.2.2.2".into()],
        };
        append_history(&path, &ev);
        append_history(&path, &ev);
        let loaded = load_history(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].new, vec!["2.2.2.2".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
