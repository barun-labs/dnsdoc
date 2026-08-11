# TIME DNS profile + persistent custom resolvers (v0.4.0)

Retroactive design note — built under an autonomous goal with a fully
specified brief (exact resolver names/IPs, exact feature description), so
the brainstorming skill's interactive Q&A and pre-approval steps were
skipped per that skill's own precedence rule (explicit user instructions
override skill process). This note exists so the decisions are on record.

## What shipped

**New builtin profile `time`** — 14 resolvers for the TIME DNS lab,
kept in a dedicated `time_resolvers()` function in `src/config.rs`,
deliberately *not* folded into `builtin_resolvers()`/the `all` profile
since these are private infra IPs, not public resolvers:

| Name | IP | Role |
|---|---|---|
| GLEN-R1 | 210.19.6.97 | recursive |
| UPM-R2 | 210.19.6.129 | recursive |
| GLEN-A1 | 210.19.6.100 | authoritative |
| UPM-A2 | 210.19.6.132 | authoritative |
| ANS-ANYCAST-1 | 210.19.6.85 | anycast VIP |
| ANS-ANYCAST-2 | 210.19.6.86 | anycast VIP |
| GLEN-C1/C2/C3 | 210.19.6.103/106/109 | cache |
| UPM-C1/C2/C3 | 210.19.6.135/138/141 | cache |
| CACHE-ANYCAST-1/2 | 210.19.6.81/82 | anycast VIP |

The user's original grouping (ANS vs CACHE-TIME) lives entirely in the
resolver names — the profile itself is a single flat list, per "add
*another profile*" (singular) in the brief.

**New builtin profile `custom`** — starts empty, filled at runtime by
pressing `a` in the TUI, typing `name ip`, Enter. Appended live to
`app.profiles` and persisted to
`~/.local/share/dnsdoc/custom_resolvers.json` (JSON array of
`{name, ip}`) so it survives restarts. Loading/saving lives in
`Config::load()`, not the pure `parse()` function, so the existing
TOML-parsing unit tests stay deterministic and don't touch disk.

## Decisions and why

- **One profile, not two** ("ans" + "cache") — matches the literal ask
  and keeps the profile picker simple; the role distinction is visible
  in each resolver's name.
- **`custom` resolvers are not merged into `all`** — keeps `all` meaning
  "the 9 public builtins", and keeps custom-server testing reversible
  (delete the JSON file, or just don't select the profile) without
  touching any other profile's behavior.
- **An empty `custom` profile is shown in the picker even with zero
  entries** — no hide-when-empty logic; one more picker row costs
  nothing and avoids state-dependent UI.
- **`a` keybind** mirrors the existing `v` (reverse lookup) popup
  pattern exactly — same input-mode priority handling, same cursor
  logic — so it reads as native to the codebase, not bolted on.

## Verification

`cargo test`: 107 passed (incl. new `time_profile_has_expected_resolvers`,
`custom_resolvers_roundtrip_disk`, `load_custom_resolvers_missing_file_is_empty`,
and two `add_open` popup key-handling tests). `cargo build --release` clean.
Deployed by rebuilding the `dnsdoc-demo` Docker image on clab-mini and
swapping the running container (same `-p 10443:7681`, same
`unless-stopped` restart policy) — confirmed via fresh image hash/binary
mtime and `curl` 200 on `http://100.64.0.3:10443/`.
