"""Tests for cspreplay. Offline: the page tests use a local HTTP server on 127.0.0.1."""
import gzip
import http.server
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cspreplay as C  # noqa: E402

PROFILE = C.load_profile()
PAGE = "https://www.shop.example/"
TRACK = "https://1688360.cc/track.js"

# Optimizely's "Example of a complete CSP policy" (support article 4410289675149, updated 17 Nov 2026),
# with the placeholders filled in.
OPTIMIZELY_EXAMPLE = (
    "default-src 'none'; "
    "frame-src https://a123.cdn.optimizely.com https://a123.cdn-pci.optimizely.com; "
    "script-src 'self' https://*.optimizely.com https://optimizely.s3.amazonaws.com "
    "https://cdn-assets-prod.s3.amazonaws.com 'nonce-r4nd0m' 'strict-dynamic'; "
    "connect-src https://logx.optimizely.com https://*.optimizely.com wss://*.optimizely.com; "
    "img-src https://cdn.optimizely.com; style-src https://*.optimizely.com 'unsafe-inline'; "
    "font-src 'self' https://*.optimizely.com")
OPTIMIZELY_SHORT = "script-src 'nonce-r4nd0m' 'strict-dynamic'"
ALLOWLIST = ("default-src 'self'; script-src 'self' https://cdn.optimizely.com; "
             "connect-src 'self' https://logx.optimizely.com; frame-src 'none'")


def verdict(csp, page=PAGE):
    return C.replay(C.parse_header(csp), page, PROFILE).verdict


class Parsing(unittest.TestCase):
    def test_directives_lowercased_and_first_wins(self):
        p = C.parse_policy("Script-Src 'self'; script-src *; ; default-src 'none'")
        self.assertEqual(p.directives["script-src"], ["'self'"])
        self.assertEqual(p.directives["default-src"], ["'none'"])

    def test_comma_separates_policies(self):
        ps = C.parse_header("script-src 'self', connect-src 'none'")
        self.assertEqual(len(ps), 2)

    def test_meta_ignores_frame_ancestors_and_report_uri(self):
        p = C.parse_policy("frame-ancestors 'none'; report-uri /r; script-src 'self'", origin="meta")
        self.assertEqual(list(p.directives), ["script-src"])

    def test_fallback_order(self):
        p = C.parse_policy("default-src 'self'; child-src https://f.example")
        self.assertEqual(p.get("frame-src")[0], "child-src")
        self.assertEqual(p.get("script-src-elem")[0], "default-src")
        p = C.parse_policy("script-src-elem 'self'; script-src 'unsafe-eval'")
        self.assertEqual(p.get("script-src-elem")[0], "script-src-elem")
        self.assertEqual(p.get("script-src")[0], "script-src")  # eval ignores script-src-elem


class Matching(unittest.TestCase):
    def m(self, expr, url, page=PAGE):
        return C.source_matches(expr, C.Url.parse(url), C.Url.parse(page))

    def test_star_and_schemes(self):
        self.assertTrue(self.m("*", TRACK))
        self.assertTrue(self.m("https:", TRACK))
        self.assertTrue(self.m("http:", TRACK))  # http: also allows the https upgrade
        self.assertFalse(self.m("data:", TRACK))

    def test_hosts(self):
        self.assertTrue(self.m("1688360.cc", TRACK))
        self.assertTrue(self.m("https://1688360.CC", TRACK))
        self.assertFalse(self.m("https://cdn.optimizely.com", TRACK))
        self.assertTrue(self.m("*.cc", TRACK))
        self.assertTrue(self.m("https://*", TRACK))
        self.assertTrue(self.m("https://*.optimizely.com", "https://cdn.optimizely.com/js/1.js"))
        self.assertFalse(self.m("https://*.optimizely.com", "https://optimizely.com/x.js"))  # apex excluded

    def test_ports_and_paths(self):
        self.assertTrue(self.m("https://1688360.cc:443", TRACK))
        self.assertFalse(self.m("https://1688360.cc:8443", TRACK))
        self.assertTrue(self.m("https://1688360.cc:*", "https://1688360.cc:8443/track.js"))
        self.assertTrue(self.m("https://1688360.cc/", TRACK))
        self.assertTrue(self.m("https://1688360.cc/track.js", TRACK))
        self.assertFalse(self.m("https://1688360.cc/lib/", TRACK))

    def test_self_and_keywords(self):
        self.assertTrue(self.m("'self'", "https://www.shop.example/app.js"))
        self.assertFalse(self.m("'self'", TRACK))
        self.assertTrue(self.m("'self'", "https://www.shop.example/a.js", "http://www.shop.example/"))
        for kw in ("'none'", "'nonce-abc'", "'sha256-AAAA'", "'unsafe-inline'", "'strict-dynamic'"):
            self.assertFalse(self.m(kw, TRACK), kw)

    def test_scheme_less_host_follows_page_scheme(self):
        self.assertFalse(self.m("1688360.cc", "http://1688360.cc/track.js", "https://www.shop.example/"))
        self.assertTrue(self.m("1688360.cc", TRACK, "http://www.shop.example/"))


class Checks(unittest.TestCase):
    def test_strict_dynamic_trusts_inserted_scripts_only(self):
        ps = C.parse_header(OPTIMIZELY_SHORT)
        self.assertTrue(C.check_script(ps, TRACK, PAGE).allowed)
        self.assertFalse(C.check_script(ps, TRACK, PAGE, parser_inserted=True).allowed)

    def test_strict_dynamic_in_default_src(self):
        ps = C.parse_header("default-src 'nonce-x' 'strict-dynamic'")
        self.assertTrue(C.check_script(ps, TRACK, PAGE).allowed)

    def test_eval_needs_unsafe_eval_in_script_src(self):
        self.assertFalse(C.check_eval(C.parse_header("script-src 'self'")).allowed)
        self.assertTrue(C.check_eval(C.parse_header("default-src 'self' 'unsafe-eval'")).allowed)
        self.assertFalse(C.check_eval(C.parse_header("default-src 'unsafe-eval'; script-src 'self'")).allowed)
        self.assertTrue(C.check_eval(C.parse_header("style-src 'self'")).allowed)  # nothing governs scripts

    def test_unsafe_inline_ignored_with_nonce_hash_or_strict_dynamic(self):
        self.assertTrue(C.check_inline(C.parse_header("script-src 'unsafe-inline'")).allowed)
        self.assertFalse(C.check_inline(C.parse_header("script-src 'unsafe-inline' 'nonce-a'")).allowed)
        self.assertFalse(C.check_inline(C.parse_header("script-src 'unsafe-inline' 'sha256-AAAA'")).allowed)
        self.assertFalse(C.check_inline(C.parse_header("script-src 'unsafe-inline' 'strict-dynamic'")).allowed)

    def test_every_enforced_policy_must_allow(self):
        ps = C.parse_header("script-src *, script-src 'self'")
        self.assertFalse(C.check_script(ps, TRACK, PAGE).allowed)

    def test_report_only_is_not_enforced(self):
        ps = C.parse_header("script-src 'self'; connect-src 'self'", "report")
        r = C.replay(ps, PAGE, PROFILE)
        self.assertEqual(r.verdict, C.NO_CSP)
        self.assertTrue(r.flags["report_only_only"])


class Verdicts(unittest.TestCase):
    def test_optimizely_example_policy(self):
        # The payload ran through 'strict-dynamic', connect-src stopped the theft, frame-src the iOS frame.
        r = C.replay(C.parse_header(OPTIMIZELY_EXAMPLE), PAGE, PROFILE)
        self.assertEqual(r.verdict, C.PAYLOAD_ONLY)
        frame = [c for stage, d, c in r.steps if d.startswith("Open a frame")][0]
        self.assertFalse(frame.allowed)
        self.assertTrue(r.flags["strict_dynamic"])
        self.assertFalse(r.flags["unsafe_eval"])

    def test_optimizely_short_form_allows_everything(self):
        self.assertEqual(verdict(OPTIMIZELY_SHORT), C.PAYLOAD_AND_THEFT)

    def test_explicit_allowlist_blocks_payload(self):
        self.assertEqual(verdict(ALLOWLIST), C.BLOCKED)

    def test_hsbc_shape_unsafe_eval_runs_inline_copy(self):
        # Report URI: HSBC's CSP blocked track.js and the theft, but 'unsafe-eval' let the inline copy run.
        csp = "script-src 'self' https://cdn.optimizely.com 'unsafe-eval'; connect-src 'self'"
        r = C.replay(C.parse_header(csp), PAGE, PROFILE)
        self.assertEqual(r.verdict, C.PAYLOAD_ONLY)
        self.assertFalse(r.steps[0][2].allowed)
        self.assertTrue(r.steps[1][2].allowed)

    def test_csp_without_script_rules(self):
        self.assertEqual(verdict("frame-ancestors 'self'; upgrade-insecure-requests"), C.PAYLOAD_AND_THEFT)

    def test_no_policy(self):
        self.assertEqual(C.replay([], PAGE, PROFILE).verdict, C.NO_CSP)

    def test_org_verdict_is_weakest_host(self):
        hosts = [{"verdict": C.BLOCKED}, {"verdict": C.PAYLOAD_ONLY}, {"verdict": C.UNREACHABLE}]
        self.assertEqual(C.org_verdict(hosts), C.PAYLOAD_ONLY)
        self.assertEqual(C.org_verdict([{"verdict": C.UNREACHABLE}]), C.UNREACHABLE)


class Detection(unittest.TestCase):
    def test_optimizely_snippets(self):
        html = '<script src="https://cdn.optimizely.com/js/6395285578973184.js"></script>'
        self.assertTrue(C.find_optimizely(html, []))
        self.assertTrue(C.find_optimizely("", ["https://opt.scheels.com/js/12345678901.js"]))
        self.assertTrue(C.find_optimizely('<script>window["optimizely"] = window["optimizely"] || []</script>', []))
        self.assertFalse(C.find_optimizely('<script src="/js/app.js"></script>', ["/js/app.js"]))


# --------------------------------------------------------------------------- local server

PAGES = {
    "/strict": ({"Content-Security-Policy": ALLOWLIST}, "<html><head></head><body>ok</body></html>"),
    "/meta": ({}, "<html><head><meta http-equiv=\"Content-Security-Policy\" content=\"" + OPTIMIZELY_SHORT +
              "\"><script src=\"https://cdn.optimizely.com/js/1234567890123.js\"></script></head></html>"),
    "/two": ({"Content-Security-Policy": ["script-src *", "script-src 'self'; connect-src 'self'"]},
             "<html></html>"),
    "/ro": ({"Content-Security-Policy-Report-Only": "default-src 'self'; report-uri /csp"}, "<html></html>"),
    "/gz": ({"Content-Security-Policy": "script-src 'self' 'unsafe-eval'"}, "<html>" + "x" * 5000 + "</html>"),
}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path in ("/redirect", "/r308"):
            self.send_response(301 if self.path == "/redirect" else 308)
            self.send_header("Location", "/strict")
            self.end_headers()
            return
        if self.path == "/cookie":  # loops forever unless the client sends the cookie back
            if "seen=1" in (self.headers.get("Cookie") or ""):
                self.path = "/strict"
            else:
                self.send_response(302)
                self.send_header("Set-Cookie", "seen=1; Path=/")
                self.send_header("Location", "/cookie")
                self.end_headers()
                return
        if self.path == "/hsbc-shape":
            headers, body = ({"Content-Security-Policy": "script-src 'self' 'unsafe-eval'; connect-src 'self'"},
                             "<html></html>")
            data = body.encode()
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path not in PAGES:
            self.send_response(403)
            self.end_headers()
            return
        headers, body = PAGES[self.path]
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in headers.items():
            for item in (v if isinstance(v, list) else [v]):
                self.send_header(k, item)
        if self.path == "/gz":
            data = gzip.compress(data)
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Pages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def page(self, path):
        return C.evaluate_page(C.fetch(self.base + path, timeout=5), PROFILE)

    def test_header_policy_blocks(self):
        p = self.page("/strict")
        self.assertEqual(p["verdict"], C.BLOCKED)

    def test_redirect_followed(self):
        p = self.page("/redirect")
        self.assertTrue(p["final_url"].endswith("/strict"))
        self.assertEqual(p["verdict"], C.BLOCKED)

    def test_meta_policy_and_snippet(self):
        p = self.page("/meta")
        self.assertEqual(p["verdict"], C.PAYLOAD_AND_THEFT)
        self.assertTrue(p["optimizely"])
        self.assertTrue(p["flags"]["strict_dynamic"])

    def test_two_headers_intersect(self):
        self.assertEqual(self.page("/two")["verdict"], C.BLOCKED)

    def test_report_only(self):
        p = self.page("/ro")
        self.assertEqual(p["verdict"], C.NO_CSP)
        self.assertTrue(p["flags"]["reporting"])

    def test_gzip_body(self):
        p = self.page("/gz")
        self.assertEqual(p["verdict"], C.PAYLOAD_AND_THEFT)  # eval fallback allowed, no connect-src
        self.assertTrue(p["flags"]["unsafe_eval"])

    def test_error_page_is_unreachable(self):
        self.assertEqual(self.page("/blocked-by-waf")["verdict"], C.UNREACHABLE)

    def test_scan_and_summary(self):
        orgs = [{"org": "A", "sector": "Retail", "domains": [self.base + "/strict", self.base + "/meta"]},
                {"org": "B", "sector": "News", "domains": [self.base + "/nothing"]}]
        result = C.scan(orgs, PROFILE, workers=4, timeout=5)
        verdicts = {o["org"]: o["verdict"] for o in result["orgs"]}
        self.assertEqual(verdicts, {"A": C.PAYLOAD_AND_THEFT, "B": C.UNREACHABLE})
        s = C.summarise(result)
        self.assertEqual(s["pages_fetched"], 2)
        self.assertEqual(s["pages_referencing_optimizely"], 1)
        json.dumps(result)  # the result must be serialisable as-is

    def test_308_redirect_followed(self):
        p = self.page("/r308")
        self.assertTrue(p["final_url"].endswith("/strict"), p.get("error"))

    def test_cookie_redirect_followed(self):
        p = self.page("/cookie")
        self.assertEqual(p["verdict"], C.BLOCKED, p.get("error"))

    def test_rescore_with_plain_loader_profile(self):
        orgs = [{"org": "Bank", "sector": "Banking", "domains": [self.base + "/hsbc-shape"]}]
        full = C.scan(orgs, PROFILE, workers=1, timeout=5)
        self.assertEqual(full["orgs"][0]["verdict"], C.PAYLOAD_ONLY)  # the eval() copy runs
        s = C.summarise(full)
        self.assertEqual(s["pages_blocking_new_script_host"], 1)
        self.assertEqual(s["orgs_blocking_new_script_host_on_every_host"], 1)
        plain = C.rescore(full, C.load_profile(C.HERE / "profiles" / "optimjack-plain-loader.json"))
        self.assertEqual(plain["orgs"][0]["verdict"], C.BLOCKED)  # the plain loader alone is stopped
        self.assertEqual(plain["pages"][0]["csp"], full["pages"][0]["csp"])  # same saved headers

    def test_cli_policy(self):
        self.assertEqual(C.main(["policy", ALLOWLIST]), 0)

    def test_cli_policy_short(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            C.main(["policy", "--short", "script-src 'self' 'unsafe-eval'; connect-src 'self'"])
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 6)  # 3 payload steps, 2 theft steps, the verdict
        self.assertIn("allowed  Run the inline copy through eval()", lines[1])
        self.assertEqual(lines[-1], "Verdict: Payload ran, but connect-src blocked the data theft")


if __name__ == "__main__":
    unittest.main()
