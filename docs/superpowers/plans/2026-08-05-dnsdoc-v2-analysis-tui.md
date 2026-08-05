# dnsdoc v2 — Analysis Depth + TUI Usability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five analysis features (DNSSEC correlation, four audit checks, latency evidence, monitor flap suppression, propagation ETA) and six TUI improvements (scrolling, live propagation rows + spinner, tab badges, latency colors + gauge, help overlay, polish) to dnsdoc.

**Architecture:** dnsdoc is a ratatui TUI over async check tasks that report via an `mpsc::Sender<Msg>` channel. Reasoning lives in pure functions in `src/checks/analysis.rs`; audit checks are pure `check_*` functions plus an async collector in `src/checks/audit.rs`. All new logic follows those two patterns. UI state lives on `App` (`src/app.rs`); all drawing in `src/ui.rs`; the event loop in `src/main.rs` polls at 100ms and drains the channel each frame.

**Tech Stack:** Rust 2024, ratatui 0.30, crossterm 0.29, hickory-proto/resolver 0.25, tokio, chrono. **No new crates.**

## Global Constraints

- No new dependencies in `Cargo.toml`.
- `cargo test` must pass without network. Network I/O only in async collectors, never in pure `check_*`/analysis functions.
- Commits: plain conventional messages (`feat: …`). NEVER add `Co-Authored-By: Claude` or any Claude/Anthropic attribution to commits or PR bodies.
- Existing key behavior must not regress: `q` quit, `Tab`/`1-5`/arrows tabs, `r` rerun, `t` rtype, `d` domain, `p`/`P` profile.
- Spec: `docs/superpowers/specs/2026-08-05-dnsdoc-v2-analysis-tui-design.md`.
- Run tests with `cargo test` from the repo root (the worktree you are in).

---

### Task 1: Analysis reasoning + four new audit checks (A1, A2, A3, A5)

**Files:**
- Modify: `src/checks/analysis.rs`
- Modify: `src/checks/audit.rs`
- Modify: `src/ui.rs` (only the two `analyze_propagation` call sites and one `synthesize` call site — signatures change)

**Interfaces:**
- Consumes: existing types `Diagnosis`, `CheckResult`, `PropagationRow`, `TraceHop`, `Severity` from `src/types.rs`; `dns::query`, `dns::raw_query`, `dns::authoritative_ns` from `src/dns.rs`.
- Produces (later tasks rely on these exact signatures):
  - `pub fn analyze_propagation(rtype: &str, auth: &[String], rows: &[PropagationRow], now: chrono::DateTime<chrono::Utc>) -> Diagnosis`
  - `pub fn synthesize(prop: Option<&Diagnosis>, prop_rows: &[PropagationRow], audit: &[CheckResult], trace: &[TraceHop]) -> Vec<Diagnosis>`
  - In `audit.rs`: `pub struct MxTargetInfo { pub target: String, pub is_ip_literal: bool, pub has_cname: bool, pub resolves: bool }`, `pub fn check_mx(infos: &[MxTargetInfo], null_mx: bool) -> CheckResult`, `pub fn check_caa(records: &[String]) -> CheckResult`, `pub fn check_ns_redundancy(ns_list: &[(String, std::net::IpAddr)]) -> CheckResult`, `pub fn check_soa_values(serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32) -> CheckResult`

- [ ] **Step 1: Write failing tests for the new/changed pure functions**

In `src/checks/analysis.rs` `mod tests` (adapt existing tests to the new signatures — pass `chrono::Utc::now()` or a fixed timestamp, and `&[]` for `prop_rows` where irrelevant):

```rust
use chrono::TimeZone;

#[test]
fn stale_ttl_evidence_includes_wallclock_eta() {
    let auth = vec!["5.6.7.8".to_string()];
    let rows = vec![
        row("good", &["5.6.7.8"], Some(true), Some(60), false),
        row("stale", &["1.2.3.4"], Some(false), Some(3600), false),
    ];
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 10, 0, 0).unwrap();
    let d = analyze_propagation("A", &auth, &rows, now);
    // 10:00 + 3600s = 11:00 UTC
    assert!(d.evidence.iter().any(|e| e.contains("11:00")), "{:?}", d.evidence);
}

#[test]
fn latency_outlier_named_in_evidence() {
    let mut rows = vec![
        row("fast1", &["1.2.3.4"], Some(true), Some(300), false),
        row("fast2", &["1.2.3.4"], Some(true), Some(300), false),
        row("slow", &["1.2.3.4"], Some(true), Some(300), false),
    ];
    rows[0].latency_ms = Some(10);
    rows[1].latency_ms = Some(12);
    rows[2].latency_ms = Some(900);
    let d = analyze_propagation("A", &["1.2.3.4".to_string()], &rows, chrono::Utc::now());
    assert!(d.evidence.iter().any(|e| e.contains("slow") && e.contains("900")));
}

#[test]
fn dnssec_broken_names_failing_resolvers() {
    let trace = vec![TraceHop {
        zone: "example.com.".into(),
        server: "x".into(),
        latency_ms: Some(10),
        note: None,
        dnssec: Some("BROKEN: DS present but no DNSKEY".into()),
        error: None,
    }];
    let rows = vec![
        row("Quad9", &[], None, None, true), // errored resolver
        row("Google", &["1.2.3.4"], Some(true), Some(60), false),
    ];
    let out = synthesize(None, &rows, &[], &trace);
    let d = out.iter().find(|d| d.headline.contains("DNSSEC")).unwrap();
    assert!(d.evidence.iter().any(|e| e.contains("Quad9")));
}

#[test]
fn slow_trace_hop_warns() {
    let trace = vec![TraceHop {
        zone: "com.".into(),
        server: "a.gtld (1.2.3.4)".into(),
        latency_ms: Some(450),
        note: None,
        dnssec: None,
        error: None,
    }];
    let out = synthesize(None, &[], &[], &trace);
    assert!(out.iter().any(|d| d.headline.contains("Slow authoritative")
        && d.severity == Severity::Warn));
}
```

In `src/checks/audit.rs` `mod tests`:

```rust
#[test]
fn caa_absent_is_ok_note() {
    let r = check_caa(&[]);
    assert_eq!(r.severity, Severity::Ok);
    assert!(r.detail.contains("any CA"));
}

#[test]
fn caa_present_lists_records() {
    let r = check_caa(&s(&["0 issue \"letsencrypt.org\""]));
    assert_eq!(r.severity, Severity::Ok);
    assert!(r.detail.contains("letsencrypt"));
}

#[test]
fn mx_null_is_ok() {
    let r = check_mx(&[], true);
    assert_eq!(r.severity, Severity::Ok);
    assert!(r.detail.to_lowercase().contains("null mx"));
}

#[test]
fn mx_unresolvable_target_errors() {
    let infos = vec![MxTargetInfo {
        target: "mail.example.com".into(),
        is_ip_literal: false,
        has_cname: false,
        resolves: false,
    }];
    assert_eq!(check_mx(&infos, false).severity, Severity::Err);
}

#[test]
fn mx_cname_target_warns() {
    let infos = vec![MxTargetInfo {
        target: "mail.example.com".into(),
        is_ip_literal: false,
        has_cname: true,
        resolves: true,
    }];
    assert_eq!(check_mx(&infos, false).severity, Severity::Warn);
}

#[test]
fn mx_ip_literal_errors() {
    let infos = vec![MxTargetInfo {
        target: "1.2.3.4".into(),
        is_ip_literal: true,
        has_cname: false,
        resolves: true,
    }];
    assert_eq!(check_mx(&infos, false).severity, Severity::Err);
}

#[test]
fn mx_healthy_ok() {
    let infos = vec![MxTargetInfo {
        target: "mail.example.com".into(),
        is_ip_literal: false,
        has_cname: false,
        resolves: true,
    }];
    assert_eq!(check_mx(&infos, false).severity, Severity::Ok);
}

#[test]
fn ns_single_warns() {
    let r = check_ns_redundancy(&[("ns1.x.com".into(), "1.2.3.4".parse().unwrap())]);
    assert_eq!(r.severity, Severity::Warn);
}

#[test]
fn ns_same_slash24_warns() {
    let r = check_ns_redundancy(&[
        ("ns1.x.com".into(), "1.2.3.4".parse().unwrap()),
        ("ns2.x.com".into(), "1.2.3.9".parse().unwrap()),
    ]);
    assert_eq!(r.severity, Severity::Warn);
    assert!(r.detail.contains("/24"));
}

#[test]
fn ns_diverse_ok() {
    let r = check_ns_redundancy(&[
        ("ns1.x.com".into(), "1.2.3.4".parse().unwrap()),
        ("ns2.x.com".into(), "8.8.4.4".parse().unwrap()),
    ]);
    assert_eq!(r.severity, Severity::Ok);
}

#[test]
fn soa_sane_values_ok() {
    let r = check_soa_values(2026080501, 7200, 3600, 1209600, 3600);
    assert_eq!(r.severity, Severity::Ok);
}

#[test]
fn soa_bad_values_warn() {
    // retry >= refresh and tiny expire
    let r = check_soa_values(1, 7200, 14400, 3600, 3600);
    assert_eq!(r.severity, Severity::Warn);
}
```

- [ ] **Step 2: Run tests, verify the new ones fail to compile / fail**

Run: `cargo test`
Expected: compile errors for missing functions/changed signatures — that is the failing state for this cycle.

- [ ] **Step 3: Implement analysis.rs changes**

1. `analyze_propagation` gains `now: chrono::DateTime<chrono::Utc>` as 4th parameter. Where the stale-TTL evidence line is built, append the ETA:

```rust
if let Some(ttl) = stale_ttl {
    let eta = now + chrono::Duration::seconds(ttl as i64);
    evidence.push(format!(
        "stale answers carry TTL up to {ttl}s ({}) before caches clear (~{} UTC)",
        approx_minutes(ttl),
        eta.format("%H:%M")
    ));
}
```

2. Latency outliers, computed over answered rows with `latency_ms`: threshold = `max(500, 5 * median)`. Evidence line names each slow resolver with its latency, e.g. `slow resolvers: slow (900ms)`. Sort latencies to get the median; skip when fewer than 3 samples.

3. `synthesize` gains `prop_rows: &[PropagationRow]` as 2nd parameter.
   - In the BROKEN-DNSSEC loop: collect `let failing: Vec<&PropagationRow> = prop_rows.iter().filter(|r| r.error.is_some()).collect();` — when non-empty AND some rows answered fine, push evidence `format!("{} resolver(s) failing now: {} — consistent with validation failure", failing.len(), names.join(", "))`.
   - New block: slow trace hops `h.latency_ms.is_some_and(|ms| ms > 200)` → one Warn diagnosis `"Slow authoritative path"` with per-hop evidence `format!("based on: {} answered in {}ms", h.server, ms)`.

4. Fix the two call sites in `src/ui.rs`: pass `chrono::Utc::now()` and `&app.prop_rows`.

- [ ] **Step 4: Implement audit.rs pure checks**

```rust
pub fn check_caa(records: &[String]) -> CheckResult {
    if records.is_empty() {
        ok("CAA", "no CAA record (any CA may issue)")
    } else {
        ok("CAA", format!("present: {}", records.join("; ")))
    }
}

pub struct MxTargetInfo {
    pub target: String,
    pub is_ip_literal: bool,
    pub has_cname: bool,
    pub resolves: bool,
}

pub fn check_mx(infos: &[MxTargetInfo], null_mx: bool) -> CheckResult {
    if null_mx {
        return ok("MX", "null MX (domain sends no mail)");
    }
    if infos.is_empty() {
        return warn("MX", "no MX records (mail falls back to A record)");
    }
    let mut problems = vec![];
    let mut sev = Severity::Ok;
    for i in infos {
        if i.is_ip_literal {
            problems.push(format!("{} is an IP literal (invalid)", i.target));
            sev = Severity::Err;
        } else if !i.resolves {
            problems.push(format!("{} does not resolve", i.target));
            sev = Severity::Err;
        } else if i.has_cname {
            problems.push(format!("{} is a CNAME (RFC 2181 violation)", i.target));
            if sev == Severity::Ok { sev = Severity::Warn; }
        }
    }
    match sev {
        Severity::Ok => ok("MX", format!("{} target(s) resolve cleanly", infos.len())),
        Severity::Warn => warn("MX", problems.join("; ")),
        Severity::Err => err("MX", problems.join("; ")),
    }
}

pub fn check_ns_redundancy(ns_list: &[(String, IpAddr)]) -> CheckResult {
    if ns_list.len() < 2 {
        return warn("NS redundancy", format!("only {} NS (2+ recommended)", ns_list.len()));
    }
    let v4_prefixes: BTreeSet<String> = ns_list
        .iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            IpAddr::V6(_) => None,
        })
        .collect();
    let v4_count = ns_list.iter().filter(|(_, ip)| ip.is_ipv4()).count();
    if v4_count == ns_list.len() && v4_prefixes.len() == 1 {
        warn("NS redundancy", format!("all {} NS in one /24 — single point of failure", ns_list.len()))
    } else {
        ok("NS redundancy", format!("{} NS across {} network(s)", ns_list.len(), v4_prefixes.len().max(1)))
    }
}

pub fn check_soa_values(serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32) -> CheckResult {
    let mut findings = vec![];
    if !(1200..=86400).contains(&refresh) {
        findings.push(format!("refresh {refresh}s outside 1200–86400"));
    }
    if retry >= refresh {
        findings.push(format!("retry {retry}s >= refresh {refresh}s"));
    }
    if expire < 604800 {
        findings.push(format!("expire {expire}s < 7d — secondaries drop the zone too soon"));
    }
    if minimum > 86400 {
        findings.push(format!("negative-cache TTL {minimum}s > 1d"));
    }
    if findings.is_empty() {
        ok("SOA sanity", format!("serial {serial}, timers sane"))
    } else {
        warn("SOA sanity", findings.join("; "))
    }
}
```

- [ ] **Step 5: Wire collectors into `audit::run`**

After the existing SOA-serials block (which already queries SOA per NS), add:

- **SOA sanity**: `dns::raw_query(ns_list[0].1, &domain, RecordType::SOA)`, read the typed record: `if let Ok(&RData::SOA(ref soa)) = r.data().try_into()` → `check_soa_values(soa.serial(), soa.refresh(), soa.retry(), soa.expire(), soa.minimum())`. Skip the check when `ns_list` is empty or no SOA parses.
- **NS redundancy**: `results.push(check_ns_redundancy(&ns_list));` (skip when `ns_list.is_empty()`).
- **CAA**: `let caa = dns::query(seed, &domain, RecordType::CAA).await; results.push(check_caa(&caa.answers));`
- **MX sanity**: the `mx` query already exists in `run()`. Parse each answer: MX rdata strings look like `"10 mail.example.com."` — split on whitespace, take the last token as target, trim trailing dot. Null MX when the only target is empty/`.` (preference 0). For each target: `is_ip_literal = target.parse::<IpAddr>().is_ok()`; `has_cname` = CNAME query at target returns answers; `resolves` = A or AAAA query at target returns answers (skip both lookups when IP literal). Build `MxTargetInfo` list, push `check_mx(&infos, null_mx)`.

- [ ] **Step 6: Run tests, verify pass**

Run: `cargo test`
Expected: all tests pass, including pre-existing ones you adapted.

- [ ] **Step 7: Commit**

```bash
git add src/checks/analysis.rs src/checks/audit.rs src/ui.rs
git commit -m "feat: DNSSEC correlation, latency evidence, propagation ETA, CAA/MX/NS/SOA audits"
```

---

### Task 2: Monitor round-robin flap suppression (A4)

**Files:**
- Modify: `src/types.rs` (`MonitorEvent`)
- Modify: `src/checks/monitor.rs`
- Modify: `src/ui.rs` (`draw_monitor` change-log rendering)

**Interfaces:**
- Consumes: `MonitorEvent`, `Msg::Monitor`, `monitor::diff`.
- Produces: `MonitorEvent` gains `#[serde(default)] pub flap: bool`. All existing constructors set `flap: false` unless flap detected.

- [ ] **Step 1: Write failing tests**

In `src/checks/monitor.rs` `mod tests` (the seen-set helper is pure):

```rust
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
```

Also extend the existing `history_roundtrip` test: construct the event with `flap: false` (compile fix) and assert a line WITHOUT the `flap` field still parses:

```rust
#[test]
fn old_history_lines_without_flap_still_parse() {
    let line = r#"{"timestamp":"2026-08-05T00:00:00Z","rtype":"A","old":["1.1.1.1"],"new":["2.2.2.2"]}"#;
    let ev: MonitorEvent = serde_json::from_str(line).unwrap();
    assert!(!ev.flap);
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test`
Expected: compile error — `note_and_check_flap` and field `flap` missing.

- [ ] **Step 3: Implement**

`src/types.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub timestamp: String,
    pub rtype: String,
    pub old: Vec<String>,
    pub new: Vec<String>,
    #[serde(default)]
    pub flap: bool,
}
```

`src/checks/monitor.rs`:

```rust
/// Record `new` in the seen-set; true when this exact answer set was already
/// seen before for this record type (round-robin rotation, not a real change).
pub fn note_and_check_flap(seen: &mut HashSet<Vec<String>>, new: &[String]) -> bool {
    let mut key = new.to_vec();
    key.sort();
    !seen.insert(key)
}
```

In `run()`: add `let mut seen: HashMap<String, HashSet<Vec<String>>> = HashMap::new();`. Seed the set with the first answer for each rtype (the `last.insert` path). When a diff fires, `let flap = note_and_check_flap(seen.entry(key.clone()).or_default(), &out.answers);` and set it on the event. Also call `note_and_check_flap` for the very first observation so the initial set counts as seen.

`src/ui.rs` `draw_monitor`: when `e.flap`, render the whole line DarkGray with a `↻ round-robin?` suffix instead of the red→green styling:

```rust
if e.flap {
    ListItem::new(Line::from(vec![
        Span::styled(format!("{} ", e.timestamp), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} {} → {} ↻ round-robin?", e.rtype, e.old.join(","), e.new.join(",")),
            Style::default().fg(Color::DarkGray)),
    ]))
} else {
    // existing red/green rendering
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/types.rs src/checks/monitor.rs src/ui.rs
git commit -m "feat: monitor flags round-robin flaps instead of logging them as changes"
```

---

### Task 3: Scrolling, help overlay, domain-input cursor (U1, U5, U6-input)

**Files:**
- Modify: `src/app.rs`
- Modify: `src/ui.rs`

**Interfaces:**
- Consumes: `App::handle_key` dispatch structure (popups first, then input mode, then global keys).
- Produces: `App` fields `pub scroll: u16`, `pub help_open: bool`, `pub input_cursor: usize` (byte-safe: treat buffer as ASCII domain chars — input already only accepts `KeyCode::Char`). Later tasks read `app.scroll` in every tab body.

- [ ] **Step 1: Write failing key-handling tests in `src/app.rs`**

```rust
#[test]
fn arrows_scroll_and_tab_switch_resets() {
    let mut a = app();
    a.handle_key(key(KeyCode::Down));
    a.handle_key(key(KeyCode::Down));
    assert_eq!(a.scroll, 2);
    a.handle_key(key(KeyCode::Up));
    assert_eq!(a.scroll, 1);
    a.handle_key(key(KeyCode::Tab));
    assert_eq!(a.scroll, 0);
}

#[test]
fn scroll_saturates_at_zero() {
    let mut a = app();
    a.handle_key(key(KeyCode::Up));
    assert_eq!(a.scroll, 0);
}

#[test]
fn question_mark_toggles_help() {
    let mut a = app();
    a.handle_key(key(KeyCode::Char('?')));
    assert!(a.help_open);
    // keys other than close keys are swallowed while help is open
    let act = a.handle_key(key(KeyCode::Char('r')));
    assert_eq!(act, Action::None);
    assert!(a.help_open);
    a.handle_key(key(KeyCode::Esc));
    assert!(!a.help_open);
}

#[test]
fn input_cursor_moves_and_inserts() {
    let mut a = app();
    a.handle_key(key(KeyCode::Char('d'))); // buf = "example.com", cursor at end
    assert_eq!(a.input_cursor, a.input_buf.len());
    a.handle_key(key(KeyCode::Home));
    assert_eq!(a.input_cursor, 0);
    a.handle_key(key(KeyCode::Char('x')));
    assert!(a.input_buf.starts_with('x'));
    assert_eq!(a.input_cursor, 1);
    a.handle_key(key(KeyCode::End));
    a.handle_key(key(KeyCode::Backspace));
    a.handle_key(key(KeyCode::Left));
    let before = a.input_cursor;
    a.handle_key(key(KeyCode::Right));
    assert_eq!(a.input_cursor, before + 1);
}
```

Note: `j`/`k` must NOT scroll — they'd be swallowed while typing is impossible, but a future search field could use them; more importantly `q` must still quit and `j`/`k` are reserved for the profile picker. Scrolling is `Up`/`Down` only.

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test`
Expected: compile errors (missing fields).

- [ ] **Step 3: Implement in `app.rs`**

- Add the three fields to `App` + `App::new` (0 / false / 0).
- `handle_key`: FIRST branch (before picker): if `help_open`, close on `Esc`/`?`/`q`, otherwise swallow (`Action::None`).
- Input mode: maintain `input_cursor` on every edit — `Char` inserts at cursor (`input_buf.insert(cursor, c)`), `Backspace` removes `cursor-1` when `cursor > 0`, `Delete` removes at cursor when in range, `Left`/`Right` saturating move, `Home`/`End` jump. Entering input mode (`d`) sets `input_cursor = input_buf.len()`.
- Global keys: `Up` → `scroll = scroll.saturating_sub(1)`, `Down` → `scroll = scroll.saturating_add(1)`, `?` → `help_open = true`.
- **Conflict fix:** `Right`/`Left` currently switch tabs. Keep that behavior (they still switch tabs; only `Up`/`Down` scroll).
- Reset `scroll = 0` in the tab-switch branches (`Tab`, `BackTab`, `Left`, `Right`, `1`-`5`) and on `DomainChanged`.

- [ ] **Step 4: Implement in `ui.rs`**

- Helper at top of file:

```rust
/// Skip `scroll` items and attach a scrollbar when content overflows.
fn scrolled_list(f: &mut Frame, area: Rect, items: Vec<ListItem<'static>>, block: Block<'static>, scroll: u16) {
    let total = items.len();
    let visible = area.height.saturating_sub(2) as usize; // borders
    let max_off = total.saturating_sub(visible);
    let off = (scroll as usize).min(max_off);
    let shown: Vec<ListItem> = items.into_iter().skip(off).collect();
    f.render_widget(List::new(shown).block(block), area);
    if total > visible {
        let mut state = ScrollbarState::new(max_off).position(off);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area,
            &mut state,
        );
    }
}
```

- Route every list body through it: audit, trace, analysis, monitor change-log. For the propagation table, apply the same skip to the row `Vec<Row>` before building `Table` (scrollbar optional there — include it with the same `ScrollbarState` math).
- Help overlay `draw_help(f)` — centered `Clear`-ed popup (~46×14) listing: `q quit · Tab/1-5/←→ tabs · ↑↓ scroll · r rerun · t record type · d domain · p/P profile · ? help`. One key per line, key column cyan. Render after the other popups in `draw()` when `app.help_open`.
- Add `?` to the idle status line text.

- [ ] **Step 5: Run tests, verify pass; build**

Run: `cargo test && cargo build`
Expected: PASS, clean build (warnings OK only if pre-existing).

- [ ] **Step 6: Commit**

```bash
git add src/app.rs src/ui.rs
git commit -m "feat: scrolling with scrollbar, help overlay, domain input cursor editing"
```

---

### Task 4: Live propagation rows + spinner + progress counter (U2)

**Files:**
- Modify: `src/types.rs` (two new `Msg` variants)
- Modify: `src/checks/propagation.rs`
- Modify: `src/app.rs`
- Modify: `src/ui.rs`
- Modify: `src/main.rs` (tick increment)

**Interfaces:**
- Consumes: Task 3's `App.scroll` (leave rendering helpers as-is).
- Produces:
  - `Msg::PropStart(usize)` — resolver count, sent once before fan-out; clears stale rows.
  - `Msg::PropRow(PropagationRow)` — one per resolver as it completes, `matches_auth` already set.
  - `App` fields: `pub prop_expected: usize`, `pub tick: u64`.
  - `pub fn spinner_frame(tick: u64) -> char` in `src/ui.rs`.

- [ ] **Step 1: Write failing tests**

In `src/app.rs`:

```rust
#[test]
fn prop_start_resets_rows_and_sets_expected() {
    let mut a = app();
    a.prop_rows.push(crate::types::PropagationRow {
        resolver: "old".into(), ip: "1.1.1.1".parse().unwrap(),
        answers: vec![], ttl: None, latency_ms: None, error: None, matches_auth: None,
    });
    a.handle_msg(Msg::PropStart(16));
    assert!(a.prop_rows.is_empty());
    assert_eq!(a.prop_expected, 16);
    let row = crate::types::PropagationRow {
        resolver: "r1".into(), ip: "1.1.1.1".parse().unwrap(),
        answers: vec!["1.2.3.4".into()], ttl: Some(60), latency_ms: Some(5),
        error: None, matches_auth: Some(true),
    };
    a.handle_msg(Msg::PropRow(row));
    assert_eq!(a.prop_rows.len(), 1);
}
```

In `src/ui.rs` (add a `#[cfg(test)] mod tests` if none exists):

```rust
#[test]
fn spinner_cycles() {
    let a = spinner_frame(0);
    let b = spinner_frame(1);
    assert_ne!(a, b);
    assert_eq!(spinner_frame(0), spinner_frame(10)); // 10 frames
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test`
Expected: compile errors (missing variants/fields/fn).

- [ ] **Step 3: Implement**

`src/types.rs` — add to `Msg`:

```rust
/// Propagation run started; payload = number of resolvers being queried.
PropStart(usize),
/// One resolver finished; row already carries matches_auth.
PropRow(PropagationRow),
```

`src/checks/propagation.rs` — restructure `run()`:

```rust
let _ = tx.send(Msg::PropStart(resolvers.len())).await;
// ... existing auth fetch unchanged ...
let futs = resolvers.into_iter().map(|r| {
    let domain = domain.clone();
    let auth = auth.clone();
    let tx = tx.clone();
    async move {
        let out = dns::query(r.ip, &domain, rtype).await;
        let mut row = PropagationRow { /* as today */ };
        row.matches_auth = mark_match(&row, auth.as_deref());
        let _ = tx.send(Msg::PropRow(row.clone())).await;
        row
    }
});
let rows: Vec<PropagationRow> = join_all(futs).await;
let _ = tx.send(Msg::Propagation(rows)).await; // final ordered set, unchanged
```

(`mark_match` moves before the loop usage; it already takes `&PropagationRow`.)

`src/app.rs` `handle_msg`:

```rust
Msg::PropStart(n) => {
    self.prop_rows.clear();
    self.prop_expected = n;
}
Msg::PropRow(row) => self.prop_rows.push(row),
```

`Msg::Propagation(rows)` keeps replacing `prop_rows` and clearing `loading` (final authoritative ordering).

`src/main.rs` — in the `loop`, right after `terminal.draw(...)`: `app.tick = app.tick.wrapping_add(1);`

`src/ui.rs`:

```rust
const SPINNER: [char; 10] = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
pub fn spinner_frame(tick: u64) -> char {
    SPINNER[(tick % 10) as usize]
}
```

- Propagation table title while `app.loading`: append `format!(" {} {}/{} answered ", spinner_frame(app.tick), app.prop_rows.len(), app.prop_expected)`.
- Diagnosis banner placeholder while loading now shows the spinner too: `format!("{} querying resolvers… {}/{}", spinner_frame(app.tick), app.prop_rows.len(), app.prop_expected)`.
- Audit/Trace loading placeholders get the spinner char prepended (no counters).

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/types.rs src/checks/propagation.rs src/app.rs src/ui.rs src/main.rs
git commit -m "feat: stream propagation rows live with spinner and answered counter"
```

---

### Task 5: Tab badges, latency colors, consensus gauge, trace glyphs, relative time, TTL countdown (U3, U4, U6-rest)

**Files:**
- Modify: `src/ui.rs`
- Modify: `src/app.rs` (monitor snapshot value type)

**Interfaces:**
- Consumes: `App.audit`, `App.prop_rows`, `App.trace`, `App.monitor_snapshot`, `consensus()` from `checks::propagation`, Task 4's spinner.
- Produces: `App.monitor_snapshot: HashMap<String, (Vec<String>, Option<u32>, std::time::Instant)>`; pure helpers in `src/ui.rs`: `fn latency_color(ms: u128) -> Color`, `pub fn relative_age(ts: &str, now: chrono::DateTime<chrono::Utc>) -> String`.

- [ ] **Step 1: Write failing tests in `src/ui.rs` tests module**

```rust
#[test]
fn latency_color_bands() {
    assert_eq!(latency_color(10), Color::Green);
    assert_eq!(latency_color(120), Color::Yellow);
    assert_eq!(latency_color(700), Color::Red);
}

#[test]
fn relative_age_formats() {
    use chrono::TimeZone;
    let now = chrono::Utc.with_ymd_and_hms(2026, 8, 5, 12, 0, 0).unwrap();
    assert_eq!(relative_age("2026-08-05T11:59:30+00:00", now), "30s ago");
    assert_eq!(relative_age("2026-08-05T11:57:00+00:00", now), "3m ago");
    assert_eq!(relative_age("2026-08-05T09:00:00+00:00", now), "3h ago");
    assert_eq!(relative_age("2026-08-01T12:00:00+00:00", now), "4d ago");
    assert_eq!(relative_age("garbage", now), "garbage"); // fall back to raw
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test`
Expected: compile errors.

- [ ] **Step 3: Implement helpers**

```rust
fn latency_color(ms: u128) -> Color {
    if ms < 50 { Color::Green } else if ms < 200 { Color::Yellow } else { Color::Red }
}

pub fn relative_age(ts: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts) else {
        return ts.to_string();
    };
    let secs = (now - t.with_timezone(&chrono::Utc)).num_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}
```

- [ ] **Step 4: Apply across the UI**

1. **Latency colors** — propagation `ms` cell: `Cell::from(...).style(Style::default().fg(latency_color(l)))` when `latency_ms` is `Some`. Trace hop latency span: same color fn instead of DarkGray.
2. **Consensus gauge** — in `draw_propagation`, insert a `Constraint::Length(1)` row between banner and table. Render `Gauge` (no block/borders): `ratio = agree as f64 / answered.max(1) as f64`, gauge color green when `agree == answered && answered > 0`, red when `agree == 0`, yellow otherwise; label `format!("{agree}/{answered} agree")`. Skip (blank) when no rows.
3. **Tab badges** in `draw_tabs` — build each title with problem counts:
   - Propagation: `✗n` red span when `n = rows with matches_auth == Some(false)` > 0.
   - Audit: `✗e` red + `!w` yellow from severity counts, omit zero parts.
   - Trace: single red `✗` when any hop has `error.is_some()`, note contains `LAME`, or dnssec contains `BROKEN`.
   - Titles become `Line::from(vec![Span::raw(" 2·Audit "), Span::styled("✗2", red), …])`.
4. **Trace glyphs** — replace `"  ".repeat(i)` indent with: depth 0 → no prefix; depth i>0 → `format!("{}└─ ", "   ".repeat(i - 1))`.
5. **TTL countdown** — change `App.monitor_snapshot` to `HashMap<String, (Vec<String>, Option<u32>, std::time::Instant)>`; `handle_msg` inserts `Instant::now()` (import `std::time::Instant` in `app.rs`). In `draw_monitor`, when `ttl` is `Some(t)`: `let left = (t as u64).saturating_sub(received.elapsed().as_secs());` display `format!("  ttl {t}s (~{left}s left)")`. Fix the `handle_msg` test if it touches snapshots.
6. **Relative timestamps** — monitor change-log lines show `relative_age(&e.timestamp, chrono::Utc::now())` (DarkGray) instead of the raw stamp; flap lines from Task 2 use it too.

- [ ] **Step 5: Run tests + build**

Run: `cargo test && cargo build`
Expected: PASS, clean build.

- [ ] **Step 6: Commit**

```bash
git add src/ui.rs src/app.rs
git commit -m "feat: tab badges, latency colors, consensus gauge, trace glyphs, relative time, ttl countdown"
```

---

## Final verification (orchestrator)

- [ ] `cargo test` — all green, no network.
- [ ] `cargo build --release` — clean.
- [ ] Manual smoke: `cargo run -- example.com` — five tabs render, `?` overlay, scrolling, spinner during load, badges after.
- [ ] Push branch, open draft PR (no Claude attribution anywhere).
