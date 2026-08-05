use std::net::IpAddr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warn,
    Err,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub severity: Severity,
    pub detail: String,
}

/// A reasoned conclusion: a plain-language call plus the evidence it rests on.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub headline: String,
    pub severity: Severity,
    /// One line per fact the headline is "based on".
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PropagationRow {
    pub resolver: String,
    pub ip: IpAddr,
    pub answers: Vec<String>,
    pub ttl: Option<u32>,
    pub latency_ms: Option<u128>,
    pub error: Option<String>,
    pub matches_auth: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct TraceHop {
    pub zone: String,
    pub server: String,
    pub latency_ms: Option<u128>,
    pub note: Option<String>,
    pub dnssec: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub timestamp: String,
    pub rtype: String,
    pub old: Vec<String>,
    pub new: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Propagation(Vec<PropagationRow>),
    AuthAnswer(Vec<String>),
    Audit(Vec<CheckResult>),
    Trace(Vec<TraceHop>),
    TraceHopArrived(TraceHop),
    Monitor(MonitorEvent),
    MonitorSnapshot {
        rtype: String,
        answers: Vec<String>,
        ttl: Option<u32>,
    },
    #[allow(dead_code)] // reserved for surfacing task errors to the status line
    Error(String),
}

pub fn validate_domain(input: &str) -> Result<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        bail!("empty domain");
    }
    if d.len() > 253 {
        bail!("domain longer than 253 chars");
    }
    for label in d.split('.') {
        if label.is_empty() {
            bail!("empty label in domain");
        }
        if label.len() > 63 {
            bail!("label longer than 63 chars");
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("invalid character in domain");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("label starts or ends with hyphen");
        }
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_domains() {
        assert_eq!(validate_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(validate_domain("a-b.co").unwrap(), "a-b.co");
        assert_eq!(validate_domain("_dmarc.example.com").unwrap(), "_dmarc.example.com");
    }

    #[test]
    fn invalid_domains() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("foo..bar").is_err());
        assert!(validate_domain("bad!char.com").is_err());
        assert!(validate_domain("-lead.com").is_err());
        assert!(validate_domain(&"a".repeat(64)).is_err());
        assert!(validate_domain(&format!("{}.com", "a.".repeat(130))).is_err());
    }
}
