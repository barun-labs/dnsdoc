use crate::app::App;
use crate::checks::analysis::{analyze_propagation, synthesize};
use crate::types::Severity;

/// Full markdown dump of all tab state. Pure fn; unit tested on a populated App.
pub fn render_markdown(app: &App) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# dnsdoc report — {}\n\nv{} · {}\n\n",
        app.domain,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    ));

    // Propagation
    out.push_str("## Propagation\n\n");
    if app.prop_rows.is_empty() {
        out.push_str("_no data_\n");
    } else {
        out.push_str("| Resolver | Answer | TTL | ms | auth-match |\n");
        out.push_str("|---|---|---|---|---|\n");
        for r in &app.prop_rows {
            let answer = match &r.error {
                Some(e) => e.clone(),
                None => r.answers.join(", "),
            };
            out.push_str(&format!(
                "| {} ({}) | {} | {} | {} | {} |\n",
                r.resolver,
                r.ip,
                answer,
                r.ttl.map(|t| t.to_string()).unwrap_or_default(),
                r.latency_ms.map(|l| l.to_string()).unwrap_or_default(),
                match r.matches_auth {
                    Some(true) => "yes",
                    Some(false) => "**no**",
                    None => "?",
                }
            ));
        }
    }
    out.push('\n');

    // Audit
    out.push_str("## Audit\n\n");
    out.push_str(&check_section(&app.audit));

    // Trace
    out.push_str("## Trace\n\n");
    if app.trace.is_empty() {
        out.push_str("_no data_\n\n");
    } else {
        for h in &app.trace {
            out.push_str(&format!(
                "- `{}` @ `{}`{}",
                h.zone,
                h.server,
                h.latency_ms.map(|l| format!(" ({l}ms)")).unwrap_or_default()
            ));
            if let Some(d) = &h.dnssec {
                out.push_str(&format!(" [{d}]"));
            }
            if let Some(n) = &h.note {
                out.push_str(&format!(" — {n}"));
            }
            if let Some(e) = &h.error {
                out.push_str(&format!(" **ERROR: {e}**"));
            }
            out.push('\n');
            for ns in &h.ns {
                out.push_str(&format!("  - {ns}\n"));
            }
        }
        out.push('\n');
    }

    // DNSSEC + Mail
    out.push_str("## DNSSEC\n\n");
    out.push_str(&check_section(&app.dnssec));
    out.push_str("## Mail\n\n");
    out.push_str(&check_section(&app.mail));

    // Sweep
    out.push_str("## Sweep\n\n");
    if app.sweep_rows.is_empty() {
        out.push_str("_no data_\n");
    } else {
        for r in &app.sweep_rows {
            out.push_str(&format!(
                "- `{}` {} — {}\n",
                r.name,
                r.rtype,
                r.answers.join(", ")
            ));
        }
    }
    out.push('\n');

    // Monitor log
    out.push_str("## Monitor log\n\n");
    if app.monitor_log.is_empty() {
        out.push_str("_no changes recorded_\n");
    } else {
        for ev in &app.monitor_log {
            out.push_str(&format!(
                "- {} {} → {}{}\n",
                ev.timestamp,
                ev.rtype,
                ev.new.join(","),
                if ev.flap { " ↻ round-robin?" } else { "" }
            ));
        }
    }
    out.push('\n');

    // Analysis
    out.push_str("## Analysis\n\n");
    let prop = if app.prop_rows.is_empty() {
        None
    } else {
        Some(analyze_propagation(
            &format!("{:?}", app.rtype),
            &app.auth_answer,
            &app.prop_rows,
            chrono::Utc::now(),
        ))
    };
    let diagnoses = synthesize(prop.as_ref(), &app.prop_rows, &app.audit, &app.trace);
    if diagnoses.is_empty() {
        out.push_str("_no findings_\n");
    } else {
        for d in &diagnoses {
            out.push_str(&format!("- **{}**\n", d.headline));
            for e in &d.evidence {
                out.push_str(&format!("  - based on: {e}\n"));
            }
        }
    }

    out
}

/// One markdown bullet per check, severity tagged.
fn check_section(checks: &[crate::types::CheckResult]) -> String {
    let mut out = String::new();
    if checks.is_empty() {
        out.push_str("_no data_\n\n");
        return out;
    }
    for c in checks {
        let tag = match c.severity {
            Severity::Ok => "OK",
            Severity::Warn => "WARN",
            Severity::Err => "ERR",
        };
        out.push_str(&format!("- [{tag}] **{}**: {}\n", c.name, c.detail));
    }
    out.push('\n');
    out
}

/// Full JSON dump of all tab state. Pure fn; output must parse as valid JSON.
pub fn render_json(app: &App) -> String {
    let propagation: Vec<serde_json::Value> = app
        .prop_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "resolver": r.resolver,
                "ip": r.ip.to_string(),
                "answers": r.answers,
                "ttl": r.ttl,
                "latency_ms": r.latency_ms,
                "error": r.error,
                "matches_auth": r.matches_auth,
            })
        })
        .collect();
    let check = |c: &crate::types::CheckResult| {
        serde_json::json!({
            "name": c.name,
            "severity": format!("{:?}", c.severity),
            "detail": c.detail,
        })
    };
    let audit: Vec<serde_json::Value> = app.audit.iter().map(check).collect();
    let dnssec: Vec<serde_json::Value> = app.dnssec.iter().map(check).collect();
    let mail: Vec<serde_json::Value> = app.mail.iter().map(check).collect();
    let trace: Vec<serde_json::Value> = app
        .trace
        .iter()
        .map(|h| {
            serde_json::json!({
                "zone": h.zone,
                "server": h.server,
                "latency_ms": h.latency_ms,
                "note": h.note,
                "ns": h.ns,
                "dnssec": h.dnssec,
                "error": h.error,
            })
        })
        .collect();
    let sweep: Vec<serde_json::Value> = app
        .sweep_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "rtype": r.rtype,
                "answers": r.answers,
            })
        })
        .collect();
    let monitor: Vec<serde_json::Value> = app
        .monitor_log
        .iter()
        .map(|ev| serde_json::to_value(ev).unwrap_or(serde_json::Value::Null))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "domain": app.domain,
        "version": env!("CARGO_PKG_VERSION"),
        "propagation": propagation,
        "audit": audit,
        "trace": trace,
        "dnssec": dnssec,
        "mail": mail,
        "sweep": sweep,
        "monitor": monitor,
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::config::Profile;
    use crate::types::*;

    fn populated() -> App {
        let mut a = App::new(
            "example.com".into(),
            vec![],
            vec![Profile { name: "all".into(), resolvers: vec![] }],
        );
        a.audit = vec![CheckResult {
            name: "SPF".into(),
            severity: Severity::Ok,
            detail: "present".into(),
        }];
        a
    }

    #[test]
    fn markdown_has_domain_and_section() {
        let md = render_markdown(&populated());
        assert!(md.contains("example.com"));
        assert!(md.contains("SPF"));
        assert!(md.contains("# dnsdoc"));
    }
    #[test]
    fn json_parses_and_has_domain() {
        let j = render_json(&populated());
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["domain"], "example.com");
    }
}
