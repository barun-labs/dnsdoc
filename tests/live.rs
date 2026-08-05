// Network integration tests. Run manually: `cargo test -- --ignored`.
// They hit real public DNS, so they are #[ignore] by default.

use std::path::PathBuf;

use dnsdoc::checks::{audit, propagation, trace};
use dnsdoc::config::builtin_resolvers;
use dnsdoc::types::Msg;
use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;

#[tokio::test]
#[ignore]
async fn propagation_gets_answers_for_example_com() {
    let (tx, mut rx) = mpsc::channel(256);
    propagation::run("example.com".into(), RecordType::A, builtin_resolvers(), tx).await;
    let mut answered = 0;
    while let Ok(msg) = rx.try_recv() {
        if let Msg::Propagation(rows) = msg {
            answered = rows.iter().filter(|r| r.error.is_none()).count();
        }
    }
    assert!(answered > 0, "expected at least one resolver to answer");
}

#[tokio::test]
#[ignore]
async fn audit_returns_results() {
    let (tx, mut rx) = mpsc::channel(256);
    audit::run("example.com".into(), tx).await;
    let mut got = 0;
    while let Ok(msg) = rx.try_recv() {
        if let Msg::Audit(r) = msg {
            got = r.len();
        }
    }
    assert!(got > 0, "expected audit findings");
}

#[tokio::test]
#[ignore]
async fn trace_reaches_authoritative() {
    let (tx, mut rx) = mpsc::channel(256);
    trace::run("example.com".into(), tx).await;
    let mut hops = 0;
    while let Ok(msg) = rx.try_recv() {
        if let Msg::Trace(h) = msg {
            hops = h.len();
        }
    }
    assert!(hops >= 2, "expected root→tld→zone hops, got {hops}");
    let _ = PathBuf::new();
}
