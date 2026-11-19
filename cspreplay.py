#!/usr/bin/env python3
"""cspreplay: replay a known web supply-chain attack against a Content Security Policy.

A CSP cannot tell good code from bad code that arrives from a host you allowed. What it can
do is refuse every *next* step: a script from a new host, an eval() fallback, a request that
carries data out, a hidden frame. This tool takes the steps a real attack needed, written
down as a profile, and asks of a policy (or a live page) which of them the browser would
have allowed.

The bundled profile is OPTIMJACK, the code injected into Optimizely Web Experimentation
snippets on 16 November 2026, with its stages taken from Report URI's published analysis.

Standard library only. Python 3.10 or later.

    python3 cspreplay.py policy "script-src 'self' https://cdn.optimizely.com"
    python3 cspreplay.py url https://www.example.com/
    python3 cspreplay.py scan data/reporturi-affected-2026-11-16.json --out results.json
    python3 cspreplay.py summary results.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import http.cookiejar
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

__version__ = "1.0.0"

HERE = Path(__file__).resolve().parent
DEFAULT_PROFILE = HERE / "profiles" / "optimjack.json"
USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/142.0.0.0 Safari/537.36")

# Which directive governs a check, and what it falls back to (CSP Level 3).
FALLBACKS = {
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src": ("script-src", "default-src"),  # eval() is checked against these two only
    "connect-src": ("connect-src", "default-src"),
    "frame-src": ("frame-src", "child-src", "default-src"),
}
# Directives a <meta> policy may not set (CSP3 section 3.3).
META_IGNORED = {"frame-ancestors", "report-uri", "sandbox"}
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# Verdicts, from weakest to strongest protection.
NO_CSP = "no-csp"
PAYLOAD_AND_THEFT = "payload-and-theft"
PAYLOAD_ONLY = "payload-only"
BLOCKED = "blocked"
UNREACHABLE = "unreachable"
ORDER = [NO_CSP, PAYLOAD_AND_THEFT, PAYLOAD_ONLY, BLOCKED]
LABELS = {
    NO_CSP: "No CSP at all",
    PAYLOAD_AND_THEFT: "CSP allowed the payload and the data theft",
    PAYLOAD_ONLY: "Payload ran, but connect-src blocked the data theft",
    BLOCKED: "Payload blocked",
    UNREACHABLE: "Could not fetch",
}


# --------------------------------------------------------------------------- parsing

@dataclass
class Policy:
    directives: dict[str, list[str]]
    disposition: str = "enforce"  # or "report"
    origin: str = "header"  # or "meta"

    def get(self, check: str) -> tuple[str | None, list[str] | None]:
        """The directive that governs `check` in this policy, after fallbacks."""
        for name in FALLBACKS[check]:
            if name in self.directives:
                return name, self.directives[name]
        return None, None


def parse_policy(text: str, disposition: str = "enforce", origin: str = "header") -> Policy:
    directives: dict[str, list[str]] = {}
    for part in text.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in directives:
            continue  # invalid names are skipped; a repeated directive is ignored (first wins)
        if origin == "meta" and name in META_IGNORED:
            continue
        directives[name] = tokens[1:]
    return Policy(directives, disposition, origin)


def parse_header(value: str, disposition: str = "enforce") -> list[Policy]:
    """One header value may carry several policies separated by commas."""
    return [parse_policy(p, disposition) for p in value.split(",") if p.strip()]


# --------------------------------------------------------------------------- matching

@dataclass(frozen=True)
class Url:
    scheme: str
    host: str
    port: int | None
    path: str

    @classmethod
    def parse(cls, url: str) -> "Url":
        s = urllib.parse.urlsplit(url)
        return cls(s.scheme.lower(), (s.hostname or "").lower(), s.port, s.path or "/")

    def effective_port(self) -> int | None:
        return self.port if self.port is not None else DEFAULT_PORTS.get(self.scheme)


def scheme_part_match(a: str, b: str) -> bool:
    """CSP3 'scheme-part match': http allows an upgrade to https, ws to wss."""
    return (a == b or (a == "http" and b == "https") or (a == "ws" and b in ("wss", "http", "https"))
            or (a == "wss" and b == "https"))


def host_part_match(pattern: str, host: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])  # "*.example.com" matches subdomains, not the apex
    return pattern == host


def port_part_match(port: str | None, url: Url) -> bool:
    if port == "*":
        return True
    if port is None:
        return url.port is None or url.port == DEFAULT_PORTS.get(url.scheme)
    return int(port) == url.effective_port()


def path_part_match(path: str, url_path: str) -> bool:
    a = urllib.parse.unquote(path)
    b = urllib.parse.unquote(url_path)
    if a in ("", "/"):
        return True
    return b.startswith(a) if a.endswith("/") else a == b


HOST_SOURCE = re.compile(
    r"(?:(?P<scheme>[a-z][a-z0-9+.-]*)://)?(?P<host>\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*)"
    r"(?::(?P<port>\*|\d+))?(?P<path>/[^?#]*)?", re.I)


def source_matches(expr: str, url: Url, page: Url) -> bool:
    """Does one source expression allow a request for `url` from a page at `page`?"""
    e = expr.lower()
    if e == "*":
        return url.scheme in ("http", "https", "ws", "wss") or url.scheme == page.scheme
    if e.startswith("'"):
        if e == "'self'":
            same_host = url.host == page.host
            if url.scheme == page.scheme and url.effective_port() == page.effective_port():
                return same_host
            # an http page's 'self' also allows the https/wss upgrade on default ports
            return (same_host and page.scheme in ("http", "ws") and url.scheme in ("https", "wss")
                    and url.port is None)
        return False  # 'none', nonces, hashes and other keywords never match an injected URL
    m = re.fullmatch(r"([a-z][a-z0-9+.-]*):", e)
    if m:
        return scheme_part_match(m.group(1), url.scheme)
    m = HOST_SOURCE.fullmatch(expr)
    if not m:
        return False
    scheme = (m.group("scheme") or "").lower()
    if scheme and not scheme_part_match(scheme, url.scheme):
        return False
    if not scheme and not scheme_part_match(page.scheme, url.scheme):
        return False
    if not host_part_match(m.group("host").lower(), url.host):
        return False
    if not port_part_match(m.group("port"), url):
        return False
    return path_part_match(m.group("path") or "", url.path)


def _keywords(tokens: list[str]) -> set[str]:
    return {t.lower() for t in tokens if t.startswith("'")}


def allow_all_inline(tokens: list[str]) -> bool:
    """CSP3: 'unsafe-inline' counts only when no nonce, hash or 'strict-dynamic' is present."""
    kws = _keywords(tokens)
    if any(k.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for k in kws):
        return False
    if "'strict-dynamic'" in kws:
        return False
    return "'unsafe-inline'" in kws


# --------------------------------------------------------------------------- checks

@dataclass
class Check:
    allowed: bool
    why: str


def _enforced(policies: list[Policy]) -> list[Policy]:
    return [p for p in policies if p.disposition == "enforce"]


def check_script(policies: list[Policy], url: str, page_url: str, parser_inserted: bool = False) -> Check:
    """A <script src> that the page's own trusted code creates (not parser-inserted)."""
    u, page = Url.parse(url), Url.parse(page_url)
    reasons = []
    for p in _enforced(policies):
        name, tokens = p.get("script-src-elem")
        if tokens is None:
            continue
        if "'strict-dynamic'" in _keywords(tokens):
            if parser_inserted:
                return Check(False, f"{name} has 'strict-dynamic', which blocks parser-inserted scripts")
            reasons.append(f"'strict-dynamic' in {name} trusts any script a trusted script inserts")
            continue
        if not any(source_matches(t, u, page) for t in tokens):
            return Check(False, f"{name} does not list {u.host}")
        reasons.append(f"{name} allows {u.host}")
    return Check(True, "; ".join(reasons) or "no script-src or default-src")


def check_eval(policies: list[Policy]) -> Check:
    reasons = []
    for p in _enforced(policies):
        name, tokens = p.get("script-src")
        if tokens is None:
            continue
        if "'unsafe-eval'" not in _keywords(tokens):
            return Check(False, f"{name} has no 'unsafe-eval'")
        reasons.append(f"'unsafe-eval' in {name}")
    return Check(True, "; ".join(reasons) or "no script-src or default-src")


def check_inline(policies: list[Policy]) -> Check:
    reasons = []
    for p in _enforced(policies):
        name, tokens = p.get("script-src-elem")
        if tokens is None:
            continue
        if not allow_all_inline(tokens):
            return Check(False, f"{name} does not allow inline scripts")
        reasons.append(f"'unsafe-inline' in {name}")
    return Check(True, "; ".join(reasons) or "no script-src or default-src")


def check_fetch(policies: list[Policy], check: str, url: str, page_url: str) -> Check:
    u, page = Url.parse(url), Url.parse(page_url)
    reasons = []
    for p in _enforced(policies):
        name, tokens = p.get(check)
        if tokens is None:
            continue
        if not any(source_matches(t, u, page) for t in tokens):
            return Check(False, f"{name} blocks {u.host}")
        reasons.append(f"{name} allows {u.host}")
    return Check(True, "; ".join(reasons) or f"no {check} or default-src")


# --------------------------------------------------------------------------- replay

def load_profile(path: Path | str = DEFAULT_PROFILE) -> dict:
    return json.loads(Path(path).read_text())


@dataclass
class Replay:
    verdict: str
    steps: list[tuple[str, str, Check]] = field(default_factory=list)  # (stage, description, result)
    flags: dict[str, bool] = field(default_factory=dict)


def flags_for(policies: list[Policy]) -> dict[str, bool]:
    enforced = _enforced(policies)
    script_lists = [p.get("script-src-elem")[1] for p in enforced if p.get("script-src-elem")[1] is not None]
    eval_lists = [p.get("script-src")[1] for p in enforced if p.get("script-src")[1] is not None]
    return {
        "enforced": bool(enforced),
        "report_only_only": bool(policies) and not enforced,
        "restricts_scripts": bool(script_lists),
        "strict_dynamic": any("'strict-dynamic'" in _keywords(t) for t in script_lists),
        "unsafe_eval": bool(eval_lists) and all("'unsafe-eval'" in _keywords(t) for t in eval_lists),
        "restricts_connect": any(p.get("connect-src")[1] is not None for p in enforced),
        "reporting": any(k in p.directives for p in policies for k in ("report-uri", "report-to")),
        "trusted_types": any("require-trusted-types-for" in p.directives for p in enforced),
    }


def replay(policies: list[Policy], page_url: str, profile: dict) -> Replay:
    enforced = _enforced(policies)
    steps: list[tuple[str, str, Check]] = []
    loader = profile["loader"]
    payload = False
    for s in loader.get("scripts", []):
        c = check_script(policies, s, page_url)
        steps.append(("payload", f"Load {s}", c))
        payload |= c.allowed
    if "eval" in loader.get("fallbacks", []):
        c = check_eval(policies)
        steps.append(("payload", "Run the inline copy through eval()", c))
        payload |= c.allowed
    if "inline" in loader.get("fallbacks", []):
        c = check_inline(policies)
        steps.append(("payload", "Run the inline copy as an inline script", c))
        payload |= c.allowed
    theft = False
    for s in profile.get("theft", {}).get("connect", []):
        c = check_fetch(policies, "connect-src", s, page_url)
        steps.append(("theft", f"Send data to {s}", c))
        theft |= c.allowed
    for s in profile.get("extra", {}).get("scripts", []):
        steps.append(("extra", f"Load {s}", check_script(policies, s, page_url)))
    for s in profile.get("extra", {}).get("frames", []):
        steps.append(("extra", f"Open a frame on {s}", check_fetch(policies, "frame-src", s, page_url)))
    if not enforced:
        verdict = NO_CSP
    elif not payload:
        verdict = BLOCKED
    elif theft:
        verdict = PAYLOAD_AND_THEFT
    else:
        verdict = PAYLOAD_ONLY
    return Replay(verdict, steps, flags_for(policies))


# --------------------------------------------------------------------------- pages

class _HeadScanner(HTMLParser):
    """Collects <meta http-equiv=content-security-policy> and script sources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and a.get("http-equiv", "").strip().lower() == "content-security-policy":
            self.meta.append(a.get("content", ""))
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])


OPTIMIZELY_PATTERNS = [
    re.compile(r"(?:cdn|cdn-pci)\.optimizely\.com/(?:js|public)/", re.I),
    re.compile(r"""window\[?["']?optimizely["']?\]?\s*=""", re.I),
]
SELF_HOSTED_SNIPPET = re.compile(r"/js/\d{10,}\.js(?:$|\?)")


def find_optimizely(html: str, scripts: list[str]) -> list[str]:
    hits = [m.group(0) for p in OPTIMIZELY_PATTERNS for m in p.finditer(html)]
    hits += [s for s in scripts if SELF_HOSTED_SNIPPET.search(s)]
    return sorted(set(hits))


def page_policies(headers_csp: list[str], headers_ro: list[str], meta: list[str]) -> list[Policy]:
    out: list[Policy] = []
    for v in headers_csp:
        out += parse_header(v, "enforce")
    for v in headers_ro:
        out += parse_header(v, "report")
    for v in meta:
        out.append(parse_policy(v, "enforce", "meta"))
    return [p for p in out if p.directives]


def _decode(body: bytes, encoding: str | None) -> bytes:
    if encoding == "gzip":
        return gzip.decompress(body)
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    return body


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Python 3.10's handler does not follow 308 Permanent Redirect; browsers do."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, 307 if code == 308 else code, msg, headers, newurl)

    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302


def fetch(url: str, timeout: float = 20.0, max_bytes: int = 3_000_000,
          context: ssl.SSLContext | None = None) -> dict:
    """GET a page the way a browser would ask for it and keep what the CSP check needs."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    # A fresh cookie jar per page: some sites set a cookie on the first redirect and expect it back.
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _Redirects(),
                                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    out = {"url": url, "final_url": None, "status": None, "error": None,
           "csp": [], "csp_report_only": [], "meta_csp": [], "optimizely": []}
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        out.update(status=e.code, final_url=e.geturl(), error=f"HTTP {e.code}")
        return out
    except Exception as e:  # DNS, TLS, timeouts: record and move on
        out["error"] = f"{type(e).__name__}: {e}"[:200]
        return out
    with resp:
        out["status"] = resp.status
        out["final_url"] = resp.geturl()
        out["csp"] = resp.headers.get_all("Content-Security-Policy") or []
        out["csp_report_only"] = resp.headers.get_all("Content-Security-Policy-Report-Only") or []
        try:
            raw = _decode(resp.read(max_bytes), resp.headers.get("Content-Encoding"))
        except Exception as e:
            out["error"] = f"body: {type(e).__name__}"
            return out
    text = raw.decode("utf-8", "replace")
    scanner = _HeadScanner()
    try:
        scanner.feed(text)
    except Exception:
        pass
    out["meta_csp"] = scanner.meta
    out["optimizely"] = find_optimizely(text, scanner.scripts)
    return out


def evaluate_page(page: dict, profile: dict) -> dict:
    if page.get("error") or not page.get("status") or page["status"] >= 400:
        return {**page, "verdict": UNREACHABLE, "flags": {}, "steps": []}
    policies = page_policies(page["csp"], page["csp_report_only"], page["meta_csp"])
    r = replay(policies, page["final_url"] or page["url"], profile)
    return {**page, "verdict": r.verdict, "flags": r.flags,
            "steps": [[stage, desc, c.allowed, c.why] for stage, desc, c in r.steps]}


# --------------------------------------------------------------------------- scanning

def host_url(domain: str) -> str:
    return domain if "://" in domain else f"https://{domain}/"


def scan(orgs: list[dict], profile: dict, workers: int = 16, timeout: float = 20.0,
         context: ssl.SSLContext | None = None) -> dict:
    urls = sorted({host_url(d) for o in orgs for d in o["domains"]})

    def one(u):
        return evaluate_page(fetch(u, timeout=timeout, context=context), profile)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        pages = {u: r for u, r in zip(urls, pool.map(one, urls))}
    org_rows = []
    for o in orgs:
        hosts = [pages[host_url(d)] for d in o["domains"]]
        org_rows.append({"org": o["org"], "sector": o.get("sector"), "verdict": org_verdict(hosts),
                         "hosts": [h["url"] for h in hosts]})
    return {"tool": f"cspreplay {__version__}", "profile": profile["name"], "pages": list(pages.values()),
            "orgs": org_rows}


def org_verdict(hosts: list[dict]) -> str:
    """Zero trust view: an organisation is only as protected as its weakest reachable host."""
    seen = [h["verdict"] for h in hosts if h["verdict"] != UNREACHABLE]
    if not seen:
        return UNREACHABLE
    return min(seen, key=ORDER.index)


def rescore(result: dict, profile: dict) -> dict:
    """Replay another profile against the headers a scan saved. Nothing is fetched."""
    pages = {p["url"]: evaluate_page({k: p[k] for k in ("url", "final_url", "status", "error", "csp",
                                                         "csp_report_only", "meta_csp", "optimizely")}, profile)
             for p in result["pages"]}
    orgs = [{**o, "verdict": org_verdict([pages[u] for u in o["hosts"]])} for o in result["orgs"]]
    return {**result, "profile": profile["name"], "pages": list(pages.values()), "orgs": orgs}


def _blocks_first_script(page: dict) -> bool:
    """Did the policy refuse the loader's first script (a script from a host it never listed)?"""
    return next((not allowed for stage, _, allowed, _ in page["steps"] if stage == "payload"), False)


def summarise(result: dict) -> dict:
    def count(rows):
        c = {k: 0 for k in ORDER + [UNREACHABLE]}
        for r in rows:
            c[r["verdict"]] += 1
        return c

    pages = result["pages"]
    by_url = {p["url"]: p for p in pages}
    ok = [p for p in pages if p["verdict"] != UNREACHABLE]
    with_csp = [p for p in ok if p["flags"].get("enforced")]
    flag = lambda k, rows: sum(1 for p in rows if p["flags"].get(k))
    org_hosts = [[by_url[u] for u in o["hosts"] if by_url[u]["verdict"] != UNREACHABLE] for o in result["orgs"]]
    org_hosts = [h for h in org_hosts if h]
    return {
        "orgs": count(result["orgs"]),
        "orgs_blocking_new_script_host_on_every_host": sum(all(map(_blocks_first_script, h)) for h in org_hosts),
        "orgs_with_optimizely_on_a_fetched_page": sum(any(p.get("optimizely") for p in h) for h in org_hosts),
        "pages": count(pages),
        "pages_blocking_new_script_host": sum(_blocks_first_script(p) for p in ok),
        "pages_fetched": len(ok),
        "pages_with_enforced_csp": len(with_csp),
        "pages_report_only_only": flag("report_only_only", ok),
        "csp_restricting_scripts": flag("restricts_scripts", with_csp),
        "csp_with_strict_dynamic": flag("strict_dynamic", with_csp),
        "csp_with_unsafe_eval": flag("unsafe_eval", with_csp),
        "csp_restricting_connect": flag("restricts_connect", with_csp),
        "pages_with_csp_reporting": flag("reporting", ok),
        "csp_with_trusted_types": flag("trusted_types", with_csp),
        "pages_referencing_optimizely": sum(1 for p in ok if p.get("optimizely")),
    }


# --------------------------------------------------------------------------- CLI

def _print_replay(r: Replay, short: bool = False) -> None:
    for stage, desc, c in r.steps:
        if short and stage == "extra":
            continue
        print(f"  [{stage:7}] {'allowed' if c.allowed else 'blocked':7}  {desc}"
              + ("" if short else f"\n              {c.why}"))
    print(f"Verdict: {LABELS[r.verdict]}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--profile", default=str(DEFAULT_PROFILE), help="attack profile JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("policy", help="replay the attack against a CSP string")
    p1.add_argument("csp")
    p1.add_argument("--page", default="https://www.example.com/", help="page the policy protects")
    p1.add_argument("--short", action="store_true", help="one line per payload and theft step, no reasons")
    p2 = sub.add_parser("url", help="fetch a page and replay the attack against its CSP")
    p2.add_argument("url")
    p3 = sub.add_parser("scan", help="fetch every host in an organisation list")
    p3.add_argument("orgs", help="JSON list of {org, sector, domains}")
    p3.add_argument("--out", required=True)
    p3.add_argument("--workers", type=int, default=16)
    p3.add_argument("--timeout", type=float, default=20.0)
    p4 = sub.add_parser("summary", help="summarise a scan result")
    p4.add_argument("result")
    p5 = sub.add_parser("rescore", help="replay --profile against a saved scan without fetching")
    p5.add_argument("result")
    p5.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    profile = load_profile(a.profile)

    if a.cmd == "policy":
        _print_replay(replay(parse_header(a.csp), a.page, profile), a.short)
    elif a.cmd == "url":
        page = evaluate_page(fetch(a.url), profile)
        if page["verdict"] == UNREACHABLE:
            print(f"Could not evaluate {a.url}: {page['error'] or page['status']}")
            return 2
        print(f"{page['final_url']}  (HTTP {page['status']})")
        for v in page["csp"]:
            print(f"  CSP: {v[:300]}")
        for v in page["meta_csp"]:
            print(f"  <meta> CSP: {v[:300]}")
        for v in page["csp_report_only"]:
            print(f"  Report-Only (not enforced): {v[:300]}")
        if page["optimizely"]:
            print(f"  Optimizely snippet: {', '.join(page['optimizely'][:3])}")
        policies = page_policies(page["csp"], page["csp_report_only"], page["meta_csp"])
        _print_replay(replay(policies, page["final_url"], profile))
    elif a.cmd == "scan":
        orgs = json.loads(Path(a.orgs).read_text())
        result = scan(orgs, profile, workers=a.workers, timeout=a.timeout)
        result["summary"] = summarise(result)
        Path(a.out).write_text(json.dumps(result, indent=1))
        print(json.dumps(result["summary"], indent=1))
    elif a.cmd == "summary":
        result = json.loads(Path(a.result).read_text())
        print(json.dumps(summarise(result), indent=1))
    elif a.cmd == "rescore":
        result = rescore(json.loads(Path(a.result).read_text()), profile)
        result["summary"] = summarise(result)
        Path(a.out).write_text(json.dumps(result, indent=1))
        print(json.dumps(result["summary"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
