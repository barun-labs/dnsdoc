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
dnsdoc example.com                # open dashboard for a domain
dnsdoc                            # start with an empty input box (press d to type)
dnsdoc example.com --profile privacy   # start on a resolver profile
```

### Keys

| Key        | Action                                  |
|------------|-----------------------------------------|
| `q`        | quit                                    |
| `Tab` / `1`–`8` | switch tab                         |
| `←` / `→`  | previous / next tab                     |
| `↑` / `↓`  | scroll the current tab                  |
| `r`        | re-run the current tab                  |
| `t`        | cycle record type (Propagation)         |
| `d`        | change domain (Enter commit, Esc cancel; `←`/`→`/Home/End move the cursor) |
| `p`        | cycle resolver profile                  |
| `P`        | profile picker (↑/↓, Enter, Esc)        |
| `e`        | export full report to `dnsdoc-<domain>-<time>.md` + `.json` |
| `v`        | reverse lookup (type an IP, Enter)      |
| `a`        | add a custom resolver (type `name ip`, Enter saves) |
| `?`        | help overlay                            |

## Tabs

- **Propagation** — queries the domain's chosen record type against 9
  reliable public resolvers plus any you configure, compares each against the
  authoritative answer, and shows a consensus verdict. Rows stream in live
  with a progress counter; a gauge shows the agree ratio and latencies are
  color-banded. Dead resolvers show their error inline and never block the
  rest. Stale answers get a wall-clock ETA for when caches clear.
- **Audit** — external health checks with OK / WARN / ERR severity: NS
  delegation consistency, NS redundancy (count + /24 spread), glue
  consistency (parent referral vs child zone), SOA serial agreement, SOA
  timer sanity + date-encoded serial decode, lame-server detection, TCP/53
  transport, EDNS support, CAA, MX target sanity (resolvable, no CNAME, no IP
  literal, null MX), CNAME chain (loops, dangling, over-long), SPF (present,
  single record, ≤10 lookups), DMARC policy, DKIM selector probe, TTL sanity,
  apex CNAME, HTTPS/SVCB and TLSA/DANE presence, open AXFR zone transfer,
  wildcard records. Authoritative checks query with recursion disabled
  (`RD=0`) and say so.
- **Trace** — iterative resolution from the root servers down to the
  authoritative NS, one hop per zone cut, with latency, the full referral NS
  set (name + glue IP) under each hop, and DNSSEC status (`signed`,
  `unsigned zone`, or `BROKEN` where the chain fails).
- **DNSSEC** — RRSIG expiry watch with a per-signature countdown (flags
  expired and expiring-soon), a resolver validation matrix (AD flag per
  resolver, DO=1), and DS↔DNSKEY chain detail per zone cut with algorithm
  names and deprecated-algorithm warnings.
- **Mail** — per-MX A/AAAA with PTR and forward-confirmed reverse DNS
  (FCrDNS), MTA-STS / TLS-RPT / BIMI record presence, and DKIM selector key
  strength (flags weak ~1024-bit RSA, notes ed25519). MTA-STS policy body is
  not fetched (HTTPS is out of scope).
- **Sweep** — probes a list of common subdomains (www, mail, api, dev,
  staging, vpn, autodiscover, _acme-challenge, ns1/ns2, …) and streams the
  hits with their records.
- **Monitor** — polls the domain on an interval (default 60s), diffs each
  poll against the last, and logs changes with relative timestamps and a TTL
  countdown per record. Answer sets seen before are tagged `↻ round-robin?`
  and dimmed instead of logged as changes. The change log persists to disk
  and reloads on the next start.
- **Analysis** — runs propagation, audit and trace and synthesizes ranked
  probable causes, each stated as a plain-language call with the evidence it rests on
  (a `based on:` line per fact). Correlations include delegation drift, zone
  version lag, broken DNSSEC cross-referenced against resolvers failing right
  now, slow authoritative paths, and resolver latency outliers. Tab titles
  carry `✗`/`!` badges so problems are visible without visiting each tab. Example: *"Still propagating — 4 of 16
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

### Resolver profiles

Four presets ship built in: **all** (9 reliable public resolvers + your
custom ones), **global** (Google/Cloudflare/Quad9/OpenDNS), **privacy**
(Quad9/AdGuard), and **custom** (empty until you add to it, see below).
Define your own on top — private infra, ISP resolver sets, whatever you
don't want baked into a public binary — and switch with `p`/`P` in the TUI
or `--profile NAME` on the CLI:

```toml
[[profile]]
name = "unifi-my"
resolvers = [
  { name = "Unifi-1", ip = "202.188.0.132" },
  { name = "Unifi-2", ip = "202.188.18.188" },
]
```

Profiles defined this way live only in your local `config.toml` — never
committed, never built into the binary. That's the right place for anything
you don't want showing up in a public repo's source or git history.

### Custom resolvers (added from the TUI)

Press `a`, type `name ip` (e.g. `lab-dns 10.0.0.53`), Enter. It's appended
to the **custom** profile immediately — no restart needed — and persisted to
`~/.local/share/dnsdoc/custom_resolvers.json` so it's there next time you
open dnsdoc. Switch to it with `p`/`P` like any other profile to run
propagation/DNSSEC checks against just your saved test servers.

Monitor history is stored at `~/.local/share/dnsdoc/history.jsonl`
(one JSON change event per line).

## Development

```bash
cargo test                # unit tests, no network
cargo test -- --ignored   # live tests against real public DNS
```

## Scope

External DNS queries only. Not included: geo/DoH region checks, HTTP fetches
(so MTA-STS policy bodies are not retrieved — only their DNS records), a
background daemon with desktop alerts, and zone-file / `named.conf` analysis.
