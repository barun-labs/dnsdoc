//! Reasoning layer. Pure functions over data the other checks already
//! collected — turns raw results into conclusions that carry their evidence.
//! No network here.

use std::collections::BTreeMap;

use crate::types::{CheckResult, Diagnosis, PropagationRow, Severity, TraceHop};

fn approx_minutes(secs: u32) -> String {
    if secs >= 60 {
        format!("~{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Diagnose propagation state from the resolver rows and the authoritative
/// answer, spelling out what the verdict is based on.
pub fn analyze_propagation(rtype: &str, auth: &[String], rows: &[PropagationRow]) -> Diagnosis {
    let answered: Vec<&PropagationRow> = rows.iter().filter(|r| r.error.is_none()).collect();
    let timeouts = rows.len() - answered.len();

    if answered.is_empty() {
        return Diagnosis {
            headline: "No resolver answered".into(),
            severity: Severity::Err,
            evidence: vec![format!("all {} resolvers timed out or errored", rows.len())],
        };
    }
    if auth.is_empty() {
        return Diagnosis {
            headline: "Cannot judge propagation — authoritative answer unknown".into(),
            severity: Severity::Warn,
            evidence: vec![
                "could not fetch the answer directly from the zone's nameservers".into(),
                format!("{} resolvers did answer, but there is nothing to compare against", answered.len()),
            ],
        };
    }

    let matching: Vec<&&PropagationRow> =
        answered.iter().filter(|r| r.matches_auth == Some(true)).collect();
    let differing: Vec<&&PropagationRow> =
        answered.iter().filter(|r| r.matches_auth == Some(false)).collect();

    let mut evidence = vec![format!("authoritative {rtype}: {}", auth.join(", "))];
    evidence.push(format!(
        "{}/{} resolvers match authoritative",
        matching.len(),
        answered.len()
    ));

    // Group the stale answers so the evidence names WHAT they serve instead.
    if !differing.is_empty() {
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for r in &differing {
            let key = if r.answers.is_empty() {
                "(empty)".to_string()
            } else {
                r.answers.join(", ")
            };
            groups.entry(key).or_default().push(r.resolver.clone());
        }
        for (ans, resolvers) in groups.iter().take(4) {
            evidence.push(format!(
                "{} resolver(s) still serve [{ans}]: {}",
                resolvers.len(),
                resolvers.join(", ")
            ));
        }
        // Worst-case wait = highest TTL still attached to a stale answer.
        let stale_ttl = differing.iter().filter_map(|r| r.ttl).max();
        if let Some(ttl) = stale_ttl {
            evidence.push(format!(
                "stale answers carry TTL up to {ttl}s ({}) before caches clear",
                approx_minutes(ttl)
            ));
        }
    }
    if timeouts > 0 {
        evidence.push(format!("{timeouts} resolver(s) timed out (excluded from the count)"));
    }

    let (headline, severity) = if differing.is_empty() {
        ("Fully propagated — every resolver matches authoritative".to_string(), Severity::Ok)
    } else if matching.is_empty() {
        (
            "Not propagated — no resolver has the authoritative answer yet".to_string(),
            Severity::Err,
        )
    } else {
        (
            format!(
                "Still propagating — {} of {} resolvers not yet updated",
                differing.len(),
                answered.len()
            ),
            Severity::Warn,
        )
    };

    Diagnosis { headline, severity, evidence }
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Err => 0,
        Severity::Warn => 1,
        Severity::Ok => 2,
    }
}

/// Cross-correlate the three checks into ranked probable causes, each with the
/// evidence it rests on. `prop` is the propagation diagnosis (may be None if
/// that tab has not run yet).
pub fn synthesize(
    prop: Option<&Diagnosis>,
    audit: &[CheckResult],
    trace: &[TraceHop],
) -> Vec<Diagnosis> {
    let mut out: Vec<Diagnosis> = vec![];

    let ns_bad = audit
        .iter()
        .find(|c| c.name == "NS delegation" && c.severity == Severity::Err);
    let lame_bad = audit
        .iter()
        .find(|c| c.name == "Lame servers" && c.severity == Severity::Err);
    let broken_dnssec: Vec<&TraceHop> = trace
        .iter()
        .filter(|h| h.dnssec.as_deref().is_some_and(|d| d.contains("BROKEN")))
        .collect();

    // Correlation: inconsistent propagation + delegation problem.
    let inconsistent = prop.is_some_and(|d| d.severity != Severity::Ok);
    if inconsistent && ns_bad.is_some() {
        out.push(Diagnosis {
            headline: "Delegation drift is the likely cause of inconsistent answers".into(),
            severity: Severity::Err,
            evidence: vec![
                format!("NS delegation check failed: {}", ns_bad.unwrap().detail),
                "resolvers reaching different nameservers get different answers".into(),
            ],
        });
    }

    // Correlation: SOA serials differ + propagation not clean → zone version lag.
    let soa_bad = audit
        .iter()
        .find(|c| c.name == "SOA serial" && c.severity != Severity::Ok);
    if inconsistent {
        if let Some(s) = soa_bad {
            out.push(Diagnosis {
                headline: "Nameservers serve different zone versions — secondary lag or stuck transfer".into(),
                severity: Severity::Warn,
                evidence: vec![
                    format!("based on: {}", s.detail),
                    "resolvers hitting the out-of-date NS answer from an older zone".into(),
                    "check zone transfer (AXFR/IXFR) or push from the primary".into(),
                ],
            });
        }
    }

    if let Some(l) = lame_bad {
        out.push(Diagnosis {
            headline: "One or more nameservers are lame — intermittent failures likely".into(),
            severity: Severity::Err,
            evidence: vec![
                format!("based on: {}", l.detail),
                "resolvers that pick the lame NS get SERVFAIL or no answer".into(),
            ],
        });
    }

    for hop in &broken_dnssec {
        out.push(Diagnosis {
            headline: "DNSSEC-validating resolvers will fail to resolve this domain".into(),
            severity: Severity::Err,
            evidence: vec![
                format!("based on: zone {} — {}", hop.zone, hop.dnssec.clone().unwrap_or_default()),
                "a broken chain of trust makes validating resolvers return SERVFAIL".into(),
            ],
        });
    }

    // Fold remaining audit ERR/WARN not already covered above.
    for c in audit {
        if c.severity == Severity::Ok {
            continue;
        }
        let already = (c.name == "NS delegation" && ns_bad.is_some() && inconsistent)
            || (c.name == "SOA serial" && soa_bad.is_some() && inconsistent)
            || (c.name == "Lame servers" && lame_bad.is_some());
        if already {
            continue;
        }
        out.push(Diagnosis {
            headline: format!("{}: {}", c.name, short(&c.detail)),
            severity: c.severity,
            evidence: vec![format!("based on: {}", c.detail)],
        });
    }

    // Propagation itself as a cause when not fully clean.
    if let Some(d) = prop {
        if d.severity != Severity::Ok {
            out.push(d.clone());
        }
    }

    if out.is_empty() {
        let mut evidence = vec![];
        if let Some(d) = prop {
            evidence.push(format!("propagation: {}", d.headline));
        }
        let oks = audit.iter().filter(|c| c.severity == Severity::Ok).count();
        if oks > 0 {
            evidence.push(format!("{oks} audit checks passed", ));
        }
        if !trace.is_empty() {
            evidence.push(format!("delegation traced cleanly through {} hops", trace.len()));
        }
        if evidence.is_empty() {
            evidence.push("run the Propagation, Audit and Trace tabs to gather evidence".into());
        }
        out.push(Diagnosis {
            headline: "No DNS problems detected".into(),
            severity: Severity::Ok,
            evidence,
        });
    }

    out.sort_by_key(|d| sev_rank(d.severity));
    out
}

fn short(s: &str) -> String {
    if s.len() > 60 {
        format!("{}…", &s[..59])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn row(resolver: &str, answers: &[&str], matches: Option<bool>, ttl: Option<u32>, err: bool) -> PropagationRow {
        PropagationRow {
            resolver: resolver.into(),
            ip: "1.1.1.1".parse::<IpAddr>().unwrap(),
            answers: answers.iter().map(|s| s.to_string()).collect(),
            ttl,
            latency_ms: Some(10),
            error: if err { Some("timeout".into()) } else { None },
            matches_auth: matches,
        }
    }

    #[test]
    fn fully_propagated_is_ok_with_evidence() {
        let auth = vec!["1.2.3.4".to_string()];
        let rows = vec![
            row("a", &["1.2.3.4"], Some(true), Some(300), false),
            row("b", &["1.2.3.4"], Some(true), Some(300), false),
        ];
        let d = analyze_propagation("A", &auth, &rows);
        assert_eq!(d.severity, Severity::Ok);
        assert!(d.evidence.iter().any(|e| e.contains("2/2")));
    }

    #[test]
    fn partial_propagation_names_stale_answer_and_ttl() {
        let auth = vec!["5.6.7.8".to_string()];
        let rows = vec![
            row("good", &["5.6.7.8"], Some(true), Some(60), false),
            row("stale1", &["1.2.3.4"], Some(false), Some(3600), false),
            row("stale2", &["1.2.3.4"], Some(false), Some(1800), false),
        ];
        let d = analyze_propagation("A", &auth, &rows);
        assert_eq!(d.severity, Severity::Warn);
        // Evidence should name the stale value and the worst-case TTL.
        assert!(d.evidence.iter().any(|e| e.contains("1.2.3.4")));
        assert!(d.evidence.iter().any(|e| e.contains("3600")));
    }

    #[test]
    fn unknown_authoritative_warns() {
        let rows = vec![row("a", &["1.2.3.4"], None, Some(300), false)];
        let d = analyze_propagation("A", &[], &rows);
        assert_eq!(d.severity, Severity::Warn);
    }

    #[test]
    fn synthesize_ranks_errors_first_and_backs_them() {
        let prop = Diagnosis {
            headline: "Still propagating".into(),
            severity: Severity::Warn,
            evidence: vec![],
        };
        let audit = vec![
            CheckResult { name: "NS delegation".into(), severity: Severity::Err, detail: "mismatch X vs Y".into() },
            CheckResult { name: "SPF".into(), severity: Severity::Ok, detail: "fine".into() },
        ];
        let out = synthesize(Some(&prop), &audit, &[]);
        assert_eq!(out[0].severity, Severity::Err);
        assert!(out[0].headline.to_lowercase().contains("delegation"));
        assert!(out[0].evidence.iter().any(|e| e.contains("mismatch")));
    }

    #[test]
    fn soa_mismatch_plus_propagation_flags_zone_lag_once() {
        let prop = Diagnosis {
            headline: "Still propagating".into(),
            severity: Severity::Warn,
            evidence: vec![],
        };
        let audit = vec![CheckResult {
            name: "SOA serial".into(),
            severity: Severity::Warn,
            detail: "serials differ across NS: [2024010101, 2024010105]".into(),
        }];
        let out = synthesize(Some(&prop), &audit, &[]);
        let lag: Vec<_> = out
            .iter()
            .filter(|d| d.headline.contains("zone versions") || d.evidence.iter().any(|e| e.contains("serials differ")))
            .collect();
        assert_eq!(lag.len(), 1, "SOA finding must appear exactly once");
        assert!(lag[0].headline.contains("secondary lag"));
    }

    #[test]
    fn synthesize_reports_healthy_when_clean() {
        let prop = Diagnosis {
            headline: "Fully propagated".into(),
            severity: Severity::Ok,
            evidence: vec![],
        };
        let audit = vec![CheckResult { name: "SPF".into(), severity: Severity::Ok, detail: "ok".into() }];
        let out = synthesize(Some(&prop), &audit, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Ok);
        assert!(out[0].headline.contains("No DNS problems"));
    }
}
