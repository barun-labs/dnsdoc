# dnsdoc

Terminal UI to diagnose DNS problems for a domain from the outside — no
zone-file access needed. Five views: propagation, config audit,
delegation/DNSSEC trace, live monitoring, and a reasoned analysis that backs
every verdict with the evidence it rests on.

## Install

```bash
cargo install --path .
# or run in place:
cargo run -- example.com
```

## Usage

```bash
dnsdoc example.com   # open dashboard for a domain
dnsdoc               # start with an empty input box (press d to type)
```

### Keys

| Key        | Action                                  |
|------------|-----------------------------------------|
| `q`        | quit                                    |
| `Tab` / `1`–`5` | switch tab                         |
| `←` / `→`  | previous / next tab                     |
| `r`        | re-run the current tab                  |
| `t`        | cycle record type (Propagation)         |
| `d`        | change domain (Enter commit, Esc cancel)|

## Tabs

- **Propagation** — queries the domain's chosen record type against ~16
  public resolvers plus any you configure, compares each against the
  authoritative answer, and shows a consensus verdict. Dead resolvers show
  their error inline and never block the rest.
- **Audit** — external health checks with OK / WARN / ERR severity: NS
  delegation consistency, SOA serial agreement, lame-server detection, SPF
  (present, single record, ≤10 lookups), DMARC policy, DKIM selector probe,
  TTL sanity, apex CNAME, open AXFR zone transfer, wildcard records.
- **Trace** — iterative resolution from the root servers down to the
  authoritative NS, one hop per zone cut, with latency and DNSSEC status
  (`signed`, `unsigned zone`, or `BROKEN` where the chain fails).
- **Monitor** — polls the domain on an interval (default 60s), diffs each
  poll against the last, and logs changes. The change log persists to disk
  and reloads on the next start.
- **Analysis** — runs all three checks and synthesizes ranked probable
  causes, each stated as a plain-language call with the evidence it rests on
  (a `based on:` line per fact). Example: *"Still propagating — 4 of 16
  resolvers not yet updated · based on: 4 resolvers still serve [1.2.3.4],
  stale answers carry TTL up to 3600s (~60m) before caches clear."* The same
  evidence banner also sits atop the Propagation tab.

Every verdict is backed by the data it was drawn from — no bare "looks
broken" without the reason.

## Config

Optional TOML at `~/.config/dnsdoc/config.toml`:

```toml
poll_interval_secs = 30

[[resolver]]
name = "MyISP"
ip = "10.0.0.53"

[[resolver]]
name = "Office"
ip = "192.168.1.1"
```

Custom resolvers are added on top of the built-in public list.

Monitor history is stored at `~/.local/share/dnsdoc/history.jsonl`
(one JSON change event per line).

## Development

```bash
cargo test                # unit tests, no network
cargo test -- --ignored   # live tests against real public DNS
```

## Scope

External queries only. Not included in v1: geo/DoH region checks, a
background daemon with desktop alerts, and zone-file / `named.conf` analysis.
