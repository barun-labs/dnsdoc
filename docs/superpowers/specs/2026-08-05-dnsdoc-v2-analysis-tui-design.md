# dnsdoc v2 — deeper analysis + TUI usability (design)

Approved scope: "do all" from the gap assessment — 5 analysis additions, 6 UI
improvements. External DNS queries only. No new crates.

## Analysis additions

### A1 — DNSSEC failure correlation (`src/checks/analysis.rs`)

`synthesize()` already emits a diagnosis per BROKEN trace hop. Strengthen it by
cross-referencing propagation rows: when a BROKEN hop exists **and** one or
more resolvers errored (SERVFAIL/timeout) while others answered, the diagnosis
evidence names those failing resolvers explicitly, e.g.
`based on: 3 resolver(s) failing now: Quad9, Cloudflare, DNS0 — consistent with validation failure`.
If no resolver errored, keep the existing wording. Pure function change; unit
tests cover both branches.

### A2 — Four new audit checks (`src/checks/audit.rs`)

Same shape as existing checks: pure `check_*` function + async collector in
`run()` + unit tests. All queries via the existing `dns::query`/`dns::raw_query`
helpers with the `8.8.8.8` seed or the already-fetched `ns_list`.

- **CAA**: query CAA at apex. No record → OK `"no CAA (any CA may issue)"`.
  Present → OK listing the record(s). Query error → Warn.
- **MX sanity**: for each MX target (MX already queried in `run()`):
  null MX (`.`) → OK `"null MX (domain sends no mail)"`; target is an IP
  literal → Err; target has a CNAME record → Warn (RFC 2181); target resolves
  to no A/AAAA → Err; otherwise OK.
- **NS redundancy**: from `ns_list`: fewer than 2 NS → Warn; all NS IPs in the
  same /24 → Warn `"all NS in one /24 — single point of failure"`; else OK.
- **SOA sanity**: parse refresh/retry/expire/minimum from the SOA already
  fetched. Warn when outside sane ranges (refresh 1200–86400, retry <
  refresh, expire > refresh, expire ≥ 604800 recommended, minimum ≤ 86400).
  Serial in YYYYMMDDnn date format gets a nod in the OK detail. If the string
  form from `dns::query` lacks the fields, use `raw_query` and read the typed
  `RData::SOA`.

### A3 — Latency evidence (`src/checks/analysis.rs`)

- `analyze_propagation`: add an evidence line when latency outliers exist
  among answered rows — any resolver > max(500 ms, 5× median). Names the slow
  resolvers.
- `synthesize`: any trace hop with `latency_ms > 200` → Warn diagnosis
  `"Slow authoritative path"` with per-hop evidence.

### A4 — Monitor round-robin flap suppression (`src/checks/monitor.rs`, `src/types.rs`, `src/ui.rs`)

`MonitorEvent` gains `#[serde(default)] pub flap: bool` (old JSONL lines still
parse). `monitor::run` keeps a per-rtype set of previously seen sorted answer
sets; a change whose new set was already seen is recorded with `flap: true`.
UI renders flap events dimmed (DarkGray) with a `↻ round-robin?` tag instead
of red→green. Real changes unchanged.

### A5 — Propagation ETA (`src/checks/analysis.rs`)

When stale answers carry a max TTL, extend that evidence line with a
wall-clock ETA: `"… before caches clear (~HH:MM UTC)"`. The pure function
takes `now: chrono::DateTime<Utc>` so tests are deterministic; `ui.rs` passes
`Utc::now()`.

## TUI improvements

### U1 — Scrolling (`src/app.rs`, `src/ui.rs`)

`App` gains `pub scroll: u16`, reset to 0 on tab switch, domain change, and
data reload. Keys `Up`/`Down`/`j`/`k` (only when no popup/input active) adjust
with saturating arithmetic. All five tab bodies honour the offset (List/Table
render from `scroll` down); a ratatui `Scrollbar` appears on the right edge
when content exceeds the viewport. Key-handling unit tests included.

### U2 — Live propagation rows + spinner (`src/types.rs`, `src/checks/propagation.rs`, `src/app.rs`, `src/ui.rs`, `src/main.rs`)

- New `Msg::PropRow(PropagationRow)`: propagation streams each row as its
  resolver answers (auth answer is fetched first, so `matches_auth` is set
  inline; `None` when auth unknown). The final `Msg::Propagation(rows)` still
  arrives last with the full ordered set (existing consumers unchanged).
- `App` gains `prop_expected: usize` (set from resolver count on spawn via a
  new field on `Action`/spawn path — simplest: `main.rs` sets it before
  spawning). Propagation table title shows `answered/expected` while loading.
- `App` gains `tick: usize`, incremented every draw-loop iteration; when
  `loading`, titles show a braille spinner frame (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`).

### U3 — Tab badges (`src/ui.rs`)

`draw_tabs` decorates titles with problem counts, computed cheaply from state
already on `App`: Propagation `✗n` when n rows mismatch; Audit `✗e !w` from
check severities; Trace `✗` when any hop has BROKEN/LAME/error. No badge when
clean or no data.

### U4 — Latency colors + consensus gauge (`src/ui.rs`)

`ms` cells colored: green < 50, yellow < 200, red ≥ 200. A one-line `Gauge`
under the diagnosis banner shows agree/answered ratio (green full, yellow
partial, red none).

### U5 — Help overlay (`src/app.rs`, `src/ui.rs`)

`?` toggles a centered popup listing every key binding; `Esc`/`?`/`q` closes.
Rendered above tab content like the profile picker.

### U6 — Polish

- Trace: tree glyphs (`└─` with depth) replace bare indentation.
- Monitor log: relative timestamps (`3m ago`, `2h ago`) computed from the
  RFC3339 stamp; absolute stamp stays in the JSONL.
- Monitor snapshot: TTL countdown — snapshot stores when it arrived
  (`Instant`), display shows `ttl 300s (~280s left)`.
- Domain input: cursor index with `Left`/`Right`/`Home`/`End` editing;
  cursor rendered at position instead of always appending.

## Non-goals

RDAP/expiry (HTTP, not DNS), geo/DoH checks, background daemon, new crates.

## Testing

Every pure function gets unit tests in-module (existing pattern). Key handling
(scroll, help toggle, input cursor) tested via `App::handle_key`. `cargo test`
green without network; `--ignored` live tests untouched.

## Execution model

Fable plans/reviews; implementation delegated to DeepSeek workers in five
sequential batches (each: worker run → `cargo test` → diff review → checkpoint
commit):

1. A1 + A2 + A3 + A5 — `analysis.rs`, `audit.rs`
2. A4 — `monitor.rs`, `types.rs`, `ui.rs`
3. U1 + U5 + U6-input — `app.rs`, `ui.rs`
4. U2 — `types.rs`, `propagation.rs`, `app.rs`, `ui.rs`, `main.rs`
5. U3 + U4 + U6-rest — `ui.rs`, `app.rs`
