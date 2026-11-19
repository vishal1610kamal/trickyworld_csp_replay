# cspreplay: replay a web supply-chain attack against a Content Security Policy

A Content Security Policy (CSP) cannot tell honest code from malicious code that arrives from a host you allowed.
What it can do is refuse every *next* step: a script from a new host, an `eval()` fallback, a request that carries
data out, a hidden frame. `cspreplay` takes the steps a real attack needed, written down as a profile, and tells you
which of them a policy (or a live page) would have allowed.

The bundled profile is **OPTIMJACK**, the code injected into Optimizely Web Experimentation snippets on
16 November 2026, with its stages taken from
[Report URI's analysis](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/).

This is the code behind the TrickyWorld article
[Zero trust lessons from x.cpe and Optimizely](https://www.trickyworld.in/computer-tricks/cyber-security/zero-trust-lessons-x-cpe-optimizely/).

Python 3.10 or newer, standard library only. It never fetches anything from the attacker hosts in a profile: they
are only addresses a policy is asked about.

## Commands

| Command | What it does |
|---|---|
| `python3 cspreplay.py policy "<policy>"` | Replays the profile against a policy string. `--page <url>` sets the page the policy protects (for `'self'`); `--short` prints one line per step. |
| `python3 cspreplay.py url https://www.example.com/checkout` | Fetches the page, reads its `Content-Security-Policy` headers, `<meta>` policies and report-only headers, and replays the profile. |
| `python3 cspreplay.py scan orgs.json --out result.json` | Fetches the home page of every host in a list of organisations, once each, and saves the headers, the replay and a summary. |
| `python3 cspreplay.py --profile <p.json> rescore result.json --out new.json` | Replays another profile against the headers a scan saved. Nothing is fetched. |
| `python3 cspreplay.py summary result.json` | Prints a scan's summary again. |

Example, a policy that lists its script hosts but keeps `'unsafe-eval'` and `'unsafe-inline'`:

```
$ python3 cspreplay.py policy --short "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.optimizely.com; connect-src 'self' https://logx.optimizely.com"
  [payload] blocked  Load https://1688360.cc/track.js
  [payload] allowed  Run the inline copy through eval()
  [payload] allowed  Run the inline copy as an inline script
  [theft  ] blocked  Send data to https://1688360.cc/card.php
  [theft  ] blocked  Send data to https://1688360.cc/hit.php
Verdict: Payload ran, but connect-src blocked the data theft
```

The verdicts are the four Report URI used: *No CSP at all*, *CSP allowed the payload and the data theft*,
*Payload ran, but connect-src blocked the data theft* (wallet-address swapping still works, because it happens
inside the page) and *Payload blocked*.

## Profiles

A profile is a JSON file with the attack's steps:

- `loader.scripts`: scripts the trusted code inserts with `document.createElement('script')` (not parser-inserted,
  so `'strict-dynamic'` trusts them), and `loader.fallbacks`: `eval` and/or `inline` copies of the payload.
- `theft.connect`: where stolen data is sent (`connect-src`).
- `extra.scripts` and `extra.frames`: further stages, reported but not part of the verdict (for OPTIMJACK, the iOS
  exploit-kit router and its hidden frame).

`profiles/optimjack.json` has all three loader versions Report URI saw (a plain `<script>`, the same URL hidden in
base64, which makes the same browser request, and a full inline copy run through `eval()`).
`profiles/optimjack-plain-loader.json` leaves the inline copy out, which is what most infected snippets carried.

## What it implements

A subset of [CSP Level 3](https://www.w3.org/TR/CSP3/), enough to answer "would this request have been allowed":

- directive fallbacks: `script-src-elem` → `script-src` → `default-src` for script elements; `script-src` →
  `default-src` for `eval()`; `connect-src` → `default-src`; `frame-src` → `child-src` → `default-src`;
- source matching: `*`, scheme sources (`https:`, with the `http:` → `https:` upgrade), hosts with `*.` wildcards,
  ports, paths and `'self'`; nonces and hashes never match an injected element;
- `'strict-dynamic'`: trusts scripts that trusted scripts insert, ignores the host list, blocks parser-inserted
  scripts; `'unsafe-inline'` counts only when no nonce, hash or `'strict-dynamic'` is present;
- several policies (several headers, or commas in one) must all allow a request; report-only policies are recorded
  but not enforced; `<meta>` policies are enforced, without `frame-ancestors`, `report-uri` and `sandbox`.

An organisation's verdict in a scan is that of its weakest reachable host: a skimmer needs only one.

## The 19 November 2026 re-check

`data/reporturi-affected-2026-11-16.json` holds the 178 organisations and the 253 hosts Report URI's write-up lists
for them (six organisations' lists were cut short there with "+N more"). On 19 November 2026, between 11:09 and
11:10 UTC, each home page was requested once from India with `cspreplay 1.0.0`. The raw results are in `results/`.

| | Pages | Organisations |
|---|---|---|
| Answered | 215 of 253 | 156 of 178 |
| No enforced CSP | 90 (16 of them report-only) | 62 |
| Allowed the payload and the data theft | 71 | 52 |
| Payload ran, data theft blocked | 54 | 42 |
| Blocked every loader version | **0** | **0** |
| Blocked a script from an unlisted host (the plain loader) | 53 | 43 on every host |

Of the 53 pages that refused an unlisted script host, all 53 still allowed `'unsafe-eval'` or `'unsafe-inline'`
(47 both). 69 of the 125 pages that enforced a policy allowed `'unsafe-eval'`, 8 used `'strict-dynamic'`, 36 pages
had CSP reporting on and none required Trusted Types. 85 pages, from 57 organisations, still referenced an
Optimizely snippet in their HTML (snippets loaded through a tag manager don't show up this way).

Report URI's count on 16 November, by its own method, was 68 organisations with no CSP, 50 that allowed the payload
and the data theft, 17 that blocked only the theft and 24 that blocked the payload, of 159. The methods differ (we
don't know which loader version each organisation's snippet carried, or how Report URI picked a host per
organisation), so the two days don't compare exactly.

Limits: home pages only, not checkout pages; 38 hosts refused, geo-blocked, failed TLS verification or timed out;
geo-redirected sites show the policy of the page served to India.

## Tests

```
python3 -m unittest discover -s tests
```

36 tests, all offline: the CSP rules above, the verdicts for Optimizely's own example policies (from its CSP guide,
updated 17 November 2026), Report URI's HSBC case, and a local HTTP server for headers, `<meta>` policies,
redirects (including 308 and cookie-based ones), gzip, error pages, scans and re-scoring. They pass on
Python 3.10.12 and 3.11.0rc1.
