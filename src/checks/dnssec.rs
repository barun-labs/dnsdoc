//! DNSSEC tab: RRSIG expiry, validation matrix, chain detail.
//! Stub — filled in by the DNSSEC task.

use tokio::sync::mpsc;

use crate::config::Resolver;
use crate::types::Msg;

pub async fn run(domain: String, _resolvers: Vec<Resolver>, tx: mpsc::Sender<Msg>) {
    let _ = domain;
    let _ = tx.send(Msg::Dnssec(vec![])).await;
}
