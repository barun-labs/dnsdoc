# dns-tester Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rust TUI (`dns-tester`) that diagnoses DNS problems externally: propagation, config audit, delegation/DNSSEC trace, live monitoring.

**Architecture:** Strict split between check modules (pure DNS logic, no UI) and ratatui UI. Tokio tasks run checks, send typed results over mpsc to the app state; UI redraws on message. Partial failures render inline.

**Tech Stack:** Rust 2021, ratatui, crossterm, tokio, hickory-resolver, hickory-client, serde/toml/serde_json, dirs, anyhow, chrono.

## Global Constraints

- External queries only; no zone-file parsing.
- Per-query timeout 2s, no retries.
- Check modules must not import ratatui; UI must not import hickory.
- Config: `~/.config/dns-tester/config.toml`; history: `~/.local/share/dns-tester/history.jsonl`.
- Unit tests use canned data, no network. Network tests marked `#[ignore]`.

## File Structure

```
Cargo.toml
src/main.rs            — arg parse, terminal setup, event loop
src/app.rs             — App state, tab enum, message handling, key handling
src/ui.rs              — all ratatui rendering (tabs, tables, tree, log)
src/types.rs           — Severity, CheckResult, PropagationRow, TraceHop, MonitorEvent, Msg
src/config.rs          — Config load/default, built-in resolver list
src/dns.rs             — query helpers (timed query w/ timeout, authoritative lookup, NS discovery)
src/checks/propagation.rs
src/checks/audit.rs
src/checks/trace.rs
src/checks/monitor.rs  — polling + JSONL history
```

---

### Task 1: Scaffold + types

**Files:** Create `Cargo.toml`, `src/main.rs` (stub), `src/types.rs`.

**Produces:**
- `Severity { Ok, Warn, Err }`, `CheckResult { name: String, severity: Severity, detail: String }`
- `PropagationRow { resolver: String, ip: IpAddr, answers: Vec<String>, ttl: Option<u32>, latency_ms: Option<u128>, error: Option<String>, matches_auth: Option<bool> }`
- `TraceHop { zone: String, server: String, latency_ms: Option<u128>, note: Option<String>, dnssec: Option<String>, error: Option<String> }`
- `MonitorEvent { timestamp: String, rtype: String, old: Vec<String>, new: Vec<String> }`
- `Msg` enum: `Propagation(Vec<PropagationRow>) | AuthAnswer(Vec<String>) | Audit(Vec<CheckResult>) | Trace(Vec<TraceHop>) | Monitor(MonitorEvent) | MonitorSnapshot(...) | Error(String)`
- `validate_domain(&str) -> Result<String>` (lowercase, trailing-dot strip, label rules)

- [ ] Step 1: `cargo init --name dns-tester`, add deps
- [ ] Step 2: write `types.rs` with unit tests for `validate_domain` (valid, empty label, bad chars, trailing dot, >253 chars)
- [ ] Step 3: `cargo test` passes
- [ ] Step 4: commit `feat: scaffold and core types`

### Task 2: Config

**Files:** Create `src/config.rs`. Test inline `#[cfg(test)]`.

**Produces:**
- `Resolver { name: String, ip: IpAddr }`
- `Config { resolvers: Vec<Resolver>, poll_interval_secs: u64, history_path: PathBuf }`
- `Config::load() -> Config` — defaults merged with optional TOML (`[[resolver]] name/ip`, `poll_interval_secs`)
- `builtin_resolvers() -> Vec<Resolver>` — ~15 entries (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS 208.67.222.222, AdGuard 94.140.14.14, DNS.SB 185.222.222.222, Comodo, CleanBrowsing, Level3, Verisign, Yandex, etc.)

- [ ] Step 1: failing test — parse TOML string adds custom resolver to builtins; bad TOML falls back to defaults
- [ ] Step 2: implement; `cargo test` passes
- [ ] Step 3: commit `feat: config with builtin resolvers`

### Task 3: DNS helpers

**Files:** Create `src/dns.rs`.

**Produces:**
- `pub async fn query(server: IpAddr, domain: &str, rtype: RecordType) -> QueryOutcome` where `QueryOutcome { answers: Vec<String>, ttl: Option<u32>, latency_ms: u128, error: Option<String> }` — hickory-client UDP query, 2s tokio timeout, answers rendered as canonical strings sorted.
- `pub async fn authoritative_ns(domain: &str) -> Result<Vec<(String, IpAddr)>>` — NS lookup via system resolver then A of each NS.
- `pub async fn authoritative_answer(domain: &str, rtype: RecordType) -> Result<Vec<String>>` — query first reachable authoritative NS directly.

Rendering helper `fn rdata_to_string(RData) -> String` unit-tested with constructed RData (A, TXT, MX). Network functions not unit-tested.

- [ ] Steps: test rdata rendering → implement → pass → commit `feat: dns query helpers`

### Task 4: Propagation check

**Files:** Create `src/checks/propagation.rs` (+ `src/checks/mod.rs`).

**Produces:**
- `pub async fn run(domain: String, rtype: RecordType, resolvers: Vec<Resolver>, tx: mpsc::Sender<Msg>)` — fetch authoritative answer (send `Msg::AuthAnswer`), fan out `dns::query` via `join_all`, mark `matches_auth = Some(sorted answers == auth)`, send `Msg::Propagation(rows)`.
- `pub fn consensus(rows: &[PropagationRow]) -> (usize, usize)` — (agreeing, answered).

- [ ] Steps: unit test `consensus` + match logic with canned rows → implement → pass → commit `feat: propagation check`

### Task 5: Audit checks

**Files:** Create `src/checks/audit.rs`.

**Produces:** `pub async fn run(domain: String, tx: mpsc::Sender<Msg>)` sending `Msg::Audit(Vec<CheckResult>)`. Pure helpers, each unit-tested with canned inputs:
- `check_ns_consistency(parent: &[String], child: &[String]) -> CheckResult`
- `check_soa_serials(serials: &[(String, Option<u32>)]) -> CheckResult`
- `check_spf(txts: &[String]) -> CheckResult` (present, one record, count `include:`/`a`/`mx`/`ptr`/`exists:`/`redirect=` ≤10)
- `check_dmarc(txt: Option<&str>) -> CheckResult` (present, extract `p=`)
- `check_ttl(ttls: &[(String, u32)]) -> CheckResult` (<60 warn, >604800 warn)
- `check_apex_cname(has_cname: bool, other_types: &[String]) -> CheckResult`
Async collectors (network, not unit-tested): parent NS via TLD servers, child NS, SOA per NS, lame-server probe (AA flag), glue presence, DKIM selector probe (`default,google,k1,s1,selector1,selector2`), open AXFR attempt (TCP), wildcard probe (`random-label-xyzq.domain`).

- [ ] Steps: tests for the six pure helpers → implement helpers → pass → implement async collector `run` → `cargo build` → commit `feat: audit checks`

### Task 6: Trace

**Files:** Create `src/checks/trace.rs`.

**Produces:** `pub async fn run(domain: String, tx: mpsc::Sender<Msg>)` — start at root hints (hardcoded a-m root IPs, pick a few), iteratively query NS referrals down to authoritative; per hop push `TraceHop`. DNSSEC: at each zone cut query DS + DNSKEY; note "signed (DS+DNSKEY ok)" / "unsigned zone (no DS)" / "BROKEN: DS present but DNSKEY missing". Lame hop: no AA and no referral → note. Helper `next_labels(domain) -> Vec<String>` ("example.com" → [".", "com.", "example.com."]) unit-tested.

- [ ] Steps: test `next_labels` → implement → pass → implement iterative loop → build → commit `feat: delegation trace with dnssec`

### Task 7: Monitor

**Files:** Create `src/checks/monitor.rs`.

**Produces:**
- `pub fn diff(old: &[String], new: &[String]) -> bool`
- `pub fn load_history(path: &Path) -> Vec<MonitorEvent>` / `pub fn append_history(path: &Path, ev: &MonitorEvent)` (JSONL, serde_json per line, ignore bad lines)
- `pub async fn run(domain: String, rtypes: Vec<RecordType>, interval: Duration, history_path: PathBuf, tx: mpsc::Sender<Msg>)` — loop: query system resolver per rtype, send `Msg::MonitorSnapshot { rtype, answers, ttl }`, on diff append + send `Msg::Monitor(event)`, sleep interval.

- [ ] Steps: tests for diff + history round-trip (tempdir) → implement → pass → implement poll loop → build → commit `feat: monitor with jsonl history`

### Task 8: App state + UI + main

**Files:** Create `src/app.rs`, `src/ui.rs`; finish `src/main.rs`.

**Produces:**
- `Tab { Propagation, Audit, Trace, Monitor }`
- `App { domain, input_mode, input_buf, tab, rtype, prop_rows, auth_answer, audit, trace, monitor_log, monitor_snapshot, status }` with `handle_key(KeyEvent) -> Action { None, Quit, Rerun, SpawnMonitor, ... }` and `handle_msg(Msg)`
- `ui::draw(&mut Frame, &App)` — tab bar, per-tab body (table / list / tree-indent list / split log+snapshot), status line with keys help
- `main.rs`: parse optional domain arg, `Config::load`, terminal raw mode + alternate screen, spawn checks for active tab on start and on `r`/tab-switch, mpsc drain in event loop (crossterm `event::poll` 100ms tick), restore terminal on exit/panic.

Key map: `q` quit, `Tab`/`1-4` tabs, `r` rerun, `t` cycle rtype, `d` domain input (Enter commit, Esc cancel).

- [ ] Steps: unit tests for `handle_key` transitions + `handle_msg` state updates → implement app.rs → pass → implement ui.rs + main.rs → `cargo build` → manual smoke `dns-tester example.com` → commit `feat: tui app shell and views`

### Task 9: Integration tests + README

**Files:** Create `tests/live.rs` (`#[ignore]` network tests: propagation on example.com answers >0 resolvers; audit returns results; trace reaches authoritative), `README.md` (install, keys, config format, screenshot placeholder-free).

- [ ] Steps: write tests → `cargo test` (ignored skipped, rest pass) → `cargo test -- --ignored` manually once → write README → commit `feat: integration tests and readme`

## Self-Review

- Spec coverage: all four tabs (T4-8), config (T2), history (T7), keys (T8), error handling (2s timeout in T3, inline errors in rows/hops), testing strategy (unit canned + ignored live). ✓
- No placeholders; signatures consistent (`Msg` defined T1, used T4-8). ✓
- Single-binary scope, one plan. ✓
