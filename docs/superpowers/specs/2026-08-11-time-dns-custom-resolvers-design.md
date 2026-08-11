# TIME DNS profile + persistent custom resolvers (v0.4.0)

Retroactive design note — built under an autonomous goal with a fully
specified brief (exact resolver names/IPs, exact feature description), so
the brainstorming skill's interactive Q&A and pre-approval steps were
skipped per that skill's own precedence rule (explicit user instructions
override skill process). This note exists so the decisions are on record.

**2026-08-12 update:** the concrete resolver list below shipped as a
builtin `time_resolvers()` in `src/config.rs` initially — this repo is
public, and a private infra IP list has no business compiled into a public
binary's source. It's been pulled out (see git history for the removal
commit) in favor of the `[[profile]]` config.toml mechanism described under
"Resolver profiles" — same as the "custom" profile below. The name/IP table
stays here **redacted**: the decisions and shape are still accurate
context, the actual addresses now live only in a local, gitignored
`config.toml` on the hosts that need them.

## What shipped

**New profile `time`** (originally builtin, now operator-supplied via
local `config.toml` — see the 2026-08-12 note above) — 14 resolvers for the
TIME DNS lab, grouped by role:

| Role | Count |
|---|---|
| recursive (GLEN + UPM) | 2 |
| authoritative (GLEN + UPM) | 2 |
| ANS anycast VIP | 2 |
| cache (GLEN ×3 + UPM ×3) | 6 |
| CACHE anycast VIP | 2 |

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

`cargo test`: 107 passed at the time of the original ship (incl.
`custom_resolvers_roundtrip_disk`, `load_custom_resolvers_missing_file_is_empty`,
and two `add_open` popup key-handling tests; the time-profile-specific test
was removed along with the builtin in the 2026-08-12 privacy fix, back down
to 106). `cargo build --release` clean. Deployed by rebuilding the
`dnsdoc-demo` Docker image on clab-mini and swapping the running container
(same `-p 10443:7681`, same `unless-stopped` restart policy) — confirmed
via fresh image hash/binary mtime and `curl` 200 on
`http://100.64.0.3:10443/`.
