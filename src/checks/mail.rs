//! Mail tab: MX, SPF, DMARC, DKIM checks.
//! Stub — filled in by the Mail task.

use tokio::sync::mpsc;

use crate::types::Msg;

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let _ = domain;
    let _ = tx.send(Msg::Mail(vec![])).await;
}
