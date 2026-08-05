# dns-tester — DNS Verifier TUI

Date: 2026-08-05
Status: Approved

## Purpose

Terminal UI tool to diagnose DNS problems for a domain from the outside
(external queries only — no zone-file/named.conf analysis). Covers the four
problems that come up most: propagation after a change, configuration health,
delegation/DNSSEC issues, and watching records over time.

## Stack

- Rust, single binary `dns-tester`
- TUI: `ratatui` + `crossterm`
- Async: `tokio`
- DNS: `hickory-resolver` / `hickory-client` (raw query control, DNSSEC support)
- Config: TOML at `~/.config/dns-tester/config.toml` (custom resolvers, poll interval)
- Monitor history: JSONL at `~/.local/share/dns-tester/history.jsonl`

## Interaction

- `dns-tester example.com` opens the dashboard for that domain; bare
  `dns-tester` opens with an input box to type a domain.
- Four tabs, switched with Tab / number keys.
- Keys: `r` re-run current tab, `t` cycle record type, `d` change domain,
  `q` quit.

## Tab 1 — Propagation

Query A/AAAA/CNAME/MX/TXT/NS against ~15 built-in public resolvers
(Google, Cloudflare, Quad9, OpenDNS, AdGuard, DNS.SB, plus regional picks)
merged with user-configured resolvers from config.toml.

- All queries parallel, 2s timeout per resolver.
- Table columns: resolver | answer | TTL | latency | match (✓/✗ vs the
  authoritative answer fetched directly from the domain's NS).
- Header shows consensus, e.g. "12/15 resolvers agree — still propagating".
- Dead/timeout resolver shows as a timeout row; never blocks the rest.

## Tab 2 — Audit

External-only health checks rendered as a severity-tagged list
(OK / WARN / ERR), each with a one-line detail:

- NS set at parent (registry) vs child (zone apex) — mismatch = delegation drift
- SOA serial identical across all NS
- Every NS reachable and answering authoritatively (lame server detection)
- Glue records present when NS is in-bailiwick
- CNAME at apex; CNAME coexisting with other record types
- SPF: present, syntax valid, ≤10 DNS lookups
- DMARC: present, policy noted
- DKIM: probe common selectors (default, google, k1, s1, selector1, selector2)
- TTL sanity: warn on <60s or extreme values
- Open AXFR: zone transfer allowed to anyone = security warning
- Wildcard record detection

## Tab 3 — Trace

Iterative resolution from root → TLD → authoritative, no recursion.

- Tree view: each delegation hop with server queried and latency.
- Flags broken delegation and lame servers at the hop where they occur.
- DNSSEC: validate DS → DNSKEY → RRSIG chain per hop; show exactly where
  the chain breaks (or "unsigned zone" when no DS).

## Tab 4 — Monitor

- Poll selected record types on interval (default 60s, configurable).
- Diff each poll against last seen values; changes go to a timestamped
  change-log panel.
- Change log persisted to JSONL, reloaded on start (history survives
  restarts).
- TTL countdown shown per record.

## Internals

- Each check is a module returning typed results:
  `CheckResult { name, severity, detail }` (audit) or check-specific structs
  (propagation rows, trace hops, monitor diffs).
- Strict boundary: check modules know nothing about ratatui; UI knows nothing
  about DNS. Tokio tasks run checks and send results over an mpsc channel;
  UI redraws on message arrival.
- Partial failure is normal: per-resolver/per-hop errors render inline,
  never crash the app.

## Error handling

- Per-query timeout 2s; retries none (a slow resolver is itself a finding).
- Network fully down: every row shows its error; app stays usable.
- Invalid domain input: validated before dispatch, inline error message.

## Testing

- Check logic unit-tested with canned DNS responses (no network).
- One integration test per tab against a stable real domain, marked
  `#[ignore]`, run manually.

## Out of scope (v1)

- Geo-distributed / DoH region checks
- Background daemon and desktop alerts
- Zone-file / named.conf analysis
