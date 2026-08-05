//! Sweep tab: probe common names (www, mail, _dmarc, …) for leftover records.
//! Stub — filled in by the Sweep task.

use tokio::sync::mpsc;

use crate::types::Msg;

pub async fn run(domain: String, tx: mpsc::Sender<Msg>) {
    let _ = domain;
    let _ = tx.send(Msg::SweepStart).await;
}
