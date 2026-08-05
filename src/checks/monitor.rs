use std::collections::{HashMap, HashSet};
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

/// Record `new` in the seen-set; true when this exact answer set was already
/// seen before for this record type (round-robin rotation, not a real change).
pub fn note_and_check_flap(seen: &mut HashSet<Vec<String>>, new: &[String]) -> bool {
    let mut key = new.to_vec();
    key.sort();
    !seen.insert(key)
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

/// Map poll latencies onto the 8 braille sparkline buckets (lowest → ▁, max → █).
pub fn sparkline(vals: &[u64]) -> String {
    if vals.is_empty() {
        return String::new();
    }
    let glyphs: Vec<char> = "▁▂▃▄▅▆▇█".chars().collect();
    let max = *vals.iter().max().unwrap();
    let min = *vals.iter().min().unwrap();
    let span = (max - min).max(1);
    vals.iter()
        .map(|v| {
            let idx = (((v - min) * 7) / span) as usize;
            glyphs[idx.min(7)]
        })
        .collect()
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
    let mut seen: HashMap<String, HashSet<Vec<String>>> = HashMap::new();

    loop {
        for rtype in &rtypes {
            let out = dns::query(seed, &domain, *rtype).await;
            let key = format!("{rtype:?}");
            // Seed/mark this observation in the seen-set (first time counts as seen).
            let flap = note_and_check_flap(seen.entry(key.clone()).or_default(), &out.answers);
            let _ = tx
                .send(Msg::MonitorSnapshot {
                    rtype: key.clone(),
                    answers: out.answers.clone(),
                    ttl: out.ttl,
                    latency_ms: out.latency_ms as u64,
                })
                .await;

            if let Some(prev) = last.get(&key) {
                if diff(prev, &out.answers) {
                    let ev = MonitorEvent {
                        timestamp: now_iso(),
                        rtype: key.clone(),
                        old: prev.clone(),
                        new: out.answers.clone(),
                        flap,
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
    fn sparkline_maps_buckets() {
        let s = sparkline(&[0, 100]);
        assert_eq!(s.chars().count(), 2);
        // lowest maps to first glyph, highest to last
        let chars: Vec<char> = "▁▂▃▄▅▆▇█".chars().collect();
        assert_eq!(s.chars().next().unwrap(), chars[0]);
        assert_eq!(s.chars().last().unwrap(), chars[7]);
    }

    #[test]
    fn sparkline_empty_is_empty() {
        assert_eq!(sparkline(&[]), "");
    }

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
            flap: false,
        };
        append_history(&path, &ev);
        append_history(&path, &ev);
        let loaded = load_history(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].new, vec!["2.2.2.2".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flap_detected_when_set_seen_before() {
        let mut seen: std::collections::HashSet<Vec<String>> = Default::default();
        let a = vec!["1.1.1.1".to_string()];
        let b = vec!["2.2.2.2".to_string()];
        assert!(!note_and_check_flap(&mut seen, &a)); // first time: not a flap
        assert!(!note_and_check_flap(&mut seen, &b)); // new set: not a flap
        assert!(note_and_check_flap(&mut seen, &a));  // back to a: flap
    }

    #[test]
    fn flap_normalizes_order() {
        let mut seen: std::collections::HashSet<Vec<String>> = Default::default();
        assert!(!note_and_check_flap(&mut seen, &["b".to_string(), "a".to_string()]));
        assert!(note_and_check_flap(&mut seen, &["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn old_history_lines_without_flap_still_parse() {
        let line = r#"{"timestamp":"2026-08-05T00:00:00Z","rtype":"A","old":["1.1.1.1"],"new":["2.2.2.2"]}"#;
        let ev: MonitorEvent = serde_json::from_str(line).unwrap();
        assert!(!ev.flap);
    }
}
