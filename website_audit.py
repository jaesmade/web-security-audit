#!/usr/bin/env python3
"""Bounded website security assessment. Python 3.10+, standard library only."""
import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit
import uuid
import xml.etree.ElementTree as ET

from audit_core import Audit as BaselineAudit, origin, local_path

VERSION = "2.0"
ACTION_PATH = re.compile(r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|reset|revoke)(?:/|$)", re.I)
REFERENCES = {
    "HTTP headers": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "CSP": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "CSRF": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "Testing guide": "https://owasp.org/www-project-web-security-testing-guide/",
}
MANUAL_REVIEW = [
    ("Authentication and recovery", "Test login, MFA, password reset, account enumeration and session rotation with dedicated accounts."),
    ("Authorization and IDOR", "Compare anonymous, user A, user B and admin access to the same objects and operations."),
    ("Injection and browser execution", "Trace actual inputs through SQL/NoSQL, templates, commands and browser DOM; validate findings in context."),
    ("CSRF and business logic", "Verify server-side enforcement on actual state changes, workflows, prices and multi-step operations."),
    ("Uploads and server-side requests", "Review validation, storage, execution permissions, URL fetching and network boundaries."),
    ("API and abuse controls", "Review endpoint/schema inventory, GraphQL, WebSockets, rate limits and resource limits."),
    ("Dependencies and build pipeline", "Run ecosystem vulnerability/advisory tools on lockfiles; review CI permissions, provenance and secret handling."),
    ("Infrastructure and deployment", "Review DNS, cloud/database policy, publish permissions, tokens, MFA, backups, logging and alerts."),
    ("TLS protocol support", "Separately assess supported protocols/ciphers; one connection cannot enumerate server support."),
]
REMEDIATIONS = {
    "Enforced CSP absent": "Develop and test an enforced Content-Security-Policy appropriate to this application.",
    "Framing protection absent": "If embedding is unnecessary, send CSP frame-ancestors 'none'.",
    "MIME sniffing protection absent": "Serve correct Content-Type values with X-Content-Type-Options: nosniff.",
    "HSTS header absent": "Consider HSTS after confirming HTTPS and the intended subdomain scope.",
    "Cookie flags to review": "Set flags appropriate to each cookie; review Secure, HttpOnly and SameSite for session cookies.",
}


def digest(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def directives(value):
    result = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            result.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return result


class PageParser(HTMLParser):
    """Collect structure only, without retaining input values or inline scripts."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.resources, self.forms, self.scripts = [], [], [], []
        self.base_href = None
        self.active_form = None
        self.inline_handlers = 0

    def handle_starttag(self, tag, attrs):
        a = {key: value or "" for key, value in attrs}
        self.inline_handlers += sum(k.lower().startswith("on") for k in a)
        if tag == "base" and self.base_href is None and a.get("href"):
            self.base_href = a["href"]
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        key = {"script": "src", "img": "src", "iframe": "src", "audio": "src", "video": "src", "source": "src", "link": "href", "object": "data"}.get(tag)
        if key and a.get(key):
            rel = set(a.get("rel", "").lower().split())
            if tag != "link" or rel & {"stylesheet", "preload", "modulepreload", "icon"}:
                self.resources.append((tag, a[key], bool(a.get("integrity"))))
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag == "form":
            method = a.get("method", "get").lower()
            self.active_form = dict(action=a.get("action", ""), method=method if method in ("get", "post", "dialog") else "get", password=False, upload=False, token_hint=False)
            self.forms.append(self.active_form)
        if tag == "input" and self.active_form is not None:
            kind = a.get("type", "text").lower()
            self.active_form["password"] |= kind == "password"
            self.active_form["upload"] |= kind == "file"
            self.active_form["token_hint"] |= bool(re.search(r"csrf|xsrf|authenticity", a.get("name", ""), re.I))

    def handle_endtag(self, tag):
        if tag == "form":
            self.active_form = None


class Audit(BaselineAudit):
    def __init__(self, base, delay=0.5, timeout=10, max_requests=160, headers=None, exclude=()):
        super().__init__(base, delay, timeout)
        self.max_requests = max_requests
        self.session_headers = headers or {}
        self.exclude = tuple(exclude)
        self.checks, self.routes, self.assets = [], [], []
        self.discovery_notes = set()
        self.halted = False
        self.tls = None
        self.source = None
        self.configuration = dict(max_requests=max_requests, delay_seconds=self.delay, timeout_seconds=timeout,
                                  excluded_prefixes=list(exclude))

    def add(self, level, title, path, detail, remediation="", confidence="observed"):
        before = len(self.findings)
        super().add(level, title, path, detail)
        if len(self.findings) > before:
            self.findings[-1].update(id=f"WEB-{len(self.findings):03d}", confidence=confidence,
                                    remediation=remediation or REMEDIATIONS.get(title, ""))

    def record(self, area, path, start, detail, complete=True):
        incomplete_titles = {"Request failed", "Response inspection truncated", "Encoded body not inspected", "Request budget or stop condition reached", "Server requested backoff"}
        complete = complete and not any(f["title"] in incomplete_titles or f["level"] == "error" for f in self.findings[start:])
        if not complete:
            self.incomplete = True
        status = "incomplete" if not complete else ("finding" if len(self.findings) > start else "no_finding")
        self.checks.append(dict(area=area, path=path, status=status, detail=detail))

    def eligible(self, url, discovered=True):
        try:
            if origin(url) != self.scope:
                return None
            p = urlsplit(url)
            path = local_path(p.path or "/")
            if p.query or any(path.startswith(prefix) for prefix in self.exclude):
                return None
            if discovered and ACTION_PATH.search(path):
                self.discovery_notes.add("Links with common state-changing path names were excluded.")
                return None
            return path
        except (ValueError, argparse.ArgumentTypeError):
            return None

    def fetch(self, url, headers=None, method="GET", allow_http=False, authenticated=True):
        target = origin(url)
        permitted_http = allow_http and target == ("http", self.scope[1], 80)
        if target != self.scope and not permitted_http:
            raise ValueError("Request blocked: URL is outside the exact target origin.")
        path = urlsplit(url).path or "/"
        if any(path.startswith(prefix) for prefix in self.exclude):
            self.incomplete = True
            return None
        if self.halted or self.requests >= self.max_requests:
            self.incomplete = True
            self.add("info", "Request budget or stop condition reached", path, "Some configured checks were not completed.", "Resolve the stop condition or increase the budget before retesting.")
            return None
        request_headers = {} if permitted_http or not authenticated else dict(self.session_headers)
        request_headers.update(headers or {})
        result = super().fetch(url, request_headers, method, allow_http)
        if result:
            status, response_headers, body = result
            self.responses[-1]["body_inspected"] = not self.responses[-1]["truncated"] and response_headers.get("Content-Encoding", "identity").lower() in ("", "identity")
            if self.responses[-1]["truncated"]:
                self.incomplete = True
                self.add("info", "Response inspection truncated", path, "Only the first 256 KiB were inspected; findings may exist beyond this limit.")
            if response_headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                self.incomplete = True
                self.add("info", "Encoded body not inspected", path, "Server ignored Accept-Encoding: identity; body checks were skipped.")
                result = status, response_headers, ""
            if status >= 400:
                self.check_disclosure(path, result[2])
            if status == 429 or (status == 503 and response_headers.get("Retry-After")):
                self.halted = True
                self.incomplete = True
                self.add("info", "Server requested backoff", path, f"HTTP {status}; further HTTP requests stopped.")
        return result

    def page(self, path):
        current = urljoin(self.base, path)
        for _ in range(6):
            result = self.fetch(current)
            if not result:
                return None
            status, headers, _ = result
            if status not in (301, 302, 303, 307, 308):
                return current, result
            location = headers.get("Location")
            if not location:
                break
            try:
                next_url = urljoin(current, location)
                allowed = origin(next_url) == self.scope
                next_path = urlsplit(next_url).path or "/"
            except ValueError:
                allowed = False
                next_path = "/"
            if not allowed or ACTION_PATH.search(next_path) or any(next_path.startswith(p) for p in self.exclude):
                self.incomplete = True
                self.add("info", "Redirect blocked by scope or exclusion", path, "No final page was inspected for this route.")
                return None
            current = next_url
        self.incomplete = True
        self.add("info", "Redirect could not be resolved", path, "Missing destination or redirect limit reached.")
        return None

    def check_http(self):
        start, response_count = len(self.findings), len(self.responses)
        super().check_http()
        complete = self.scope[0] == "http" or len(self.responses) > response_count
        if self.scope[0] == "https" and self.scope[2] != 443:
            self.checks.append(dict(area="HTTP upgrade", path="/", status="not_tested", detail="Nonstandard HTTPS port; HTTP port was not inferred."))
        else:
            self.record("HTTP upgrade", "/", start, "One anonymous HTTP request at most; no redirect followed.", complete)

    def check_tls(self):
        start = len(self.findings)
        if self.scope[0] != "https":
            self.checks.append(dict(area="TLS", path="/", status="not_tested", detail="HTTP target."))
            return
        try:
            pause = self.delay - (time.monotonic() - self.last_request)
            if pause > 0:
                time.sleep(pause)
            self.last_request = time.monotonic()
            context = ssl.create_default_context()
            with socket.create_connection((self.scope[1], self.scope[2]), self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=self.scope[1]) as conn:
                    cert = conn.getpeercert()
                    expires = ssl.cert_time_to_seconds(cert["notAfter"])
                    remaining = (expires - time.time()) / 86400
                    cipher = conn.cipher()
                    self.tls = dict(validated=True, protocol=conn.version(), cipher=cipher[0] if cipher else None,
                                    certificate_expires_utc=datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                                    days_remaining=round(remaining, 1), connections=1)
                    if remaining < 30:
                        self.add("low", "Certificate expires soon", "/", f"Validated certificate has {remaining:.1f} days remaining.", "Confirm renewal and monitor expiration.")
            self.record("TLS", "/", start, "One direct validated handshake; negotiated protocol/cipher and expiry only.")
        except (OSError, ValueError, KeyError) as exc:
            self.add("error", "TLS assessment failed", "/", f"{type(exc).__name__}; direct connection validation did not complete.")
            self.record("TLS", "/", start, "Direct connection may differ from HTTP proxy routing.", False)

    def check_policies(self, path, headers, is_html):
        hsts = headers.get("Strict-Transport-Security", "")
        if self.scope[0] == "https" and hsts:
            age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
            if not age or int(age[1]) == 0:
                self.add("low", "HSTS disabled or malformed", path, "No positive max-age directive was recognized.", "Send a valid positive max-age after testing HTTPS.")
        if not is_html:
            if headers.get("X-Content-Type-Options", "").strip().lower() != "nosniff":
                self.add("low", "MIME sniffing protection absent", path, "X-Content-Type-Options: nosniff was not observed.")
            return
        xfo = headers.get("X-Frame-Options", "").strip().upper()
        policies = headers.get_all("Content-Security-Policy", [])
        if not policies:
            if xfo and xfo not in ("DENY", "SAMEORIGIN"):
                self.add("low", "Unrecognized framing header", path, "X-Frame-Options is not DENY or SAMEORIGIN.", "Use a supported frame-ancestors policy.")
            if headers.get("Content-Security-Policy-Report-Only"):
                self.add("info", "CSP is report-only", path, "Report-only policies do not block violations.", "Test the policy, then deliver an enforced version.")
            return
        if len(policies) > 1 or any("," in p for p in policies):
            self.add("info", "Multiple CSP policies require review", path, "Policy intersection requires browser-aware analysis; policies were not merged.")
            return
        policy = directives(policies[0])
        script = policy.get("script-src", policy.get("default-src", []))
        for keyword in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:"):
            if keyword not in script:
                continue
            nonce_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
            if keyword == "'unsafe-inline'" and nonce_hash:
                continue
            self.add("low", "Permissive script CSP to review", path, f"Script source policy contains {keyword}; effective browser semantics need review.",
                     "Use explicit sources or nonces/hashes; remove unnecessary execution allowances.", "heuristic")
        if "script-src" not in policy and "default-src" not in policy:
            self.add("low", "CSP does not restrict script sources", path, "Neither script-src nor default-src was recognized.", "Define a tested script source policy.")
        for name in ("object-src", "base-uri"):
            if name not in policy and (name == "base-uri" or "default-src" not in policy):
                self.add("info", "CSP directive to review", path, f"{name} has no recognized restriction.", "Review whether a restrictive directive suits the application.")
        if "frame-ancestors" in policy and policy["frame-ancestors"] in ([], ["*"]):
            self.add("low", "Framing policy allows any ancestor", path, "frame-ancestors uses a wildcard; browser embedding was not tested.", "Use an explicit allowlist or 'none'.")
        if xfo and xfo not in ("DENY", "SAMEORIGIN") and "frame-ancestors" not in policy:
            self.add("low", "Unrecognized framing header", path, "X-Frame-Options is not DENY or SAMEORIGIN.", "Use a supported frame-ancestors policy.")

    def check_cookie_details(self, path, headers):
        from http.cookies import SimpleCookie, CookieError
        for raw in headers.get_all("Set-Cookie", []):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except CookieError:
                cookie = SimpleCookie()
            if not cookie:
                self.add("info", "Cookie could not be parsed", path, "Flags were not fully inspected; names and values were omitted.")
            for name, morsel in cookie.items():
                if morsel["samesite"] and morsel["samesite"].lower() not in ("lax", "strict", "none"):
                    self.add("low", "Unrecognized SameSite value", path, "A cookie has an unrecognized SameSite value.", "Use Lax, Strict or None as appropriate.")
                if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                    self.add("low", "SameSite=None cookie lacks Secure", path, "Modern browsers may reject this cookie.", "Use Secure when SameSite=None is required.")
                if name.startswith("__Host-") and (not morsel["secure"] or morsel["domain"] or morsel["path"] != "/"):
                    self.add("low", "Invalid __Host- cookie attributes", path, "Prefix requirements were not met.", "Use Secure, Path=/ and no Domain attribute.")
                if name.startswith("__Secure-") and not morsel["secure"]:
                    self.add("low", "Invalid __Secure- cookie attributes", path, "Prefix requires Secure.", "Set Secure on the prefixed cookie.")

    def check_disclosure(self, path, body):
        signatures = (r"Traceback \(most recent call last\):", r"SQLSTATE\[[0-9A-Z]{5}\]",
                      r"Fatal error:.*? on line \d+", r"You.re seeing this error because you have DEBUG = True")
        if any(re.search(pattern, body, re.I | re.S) for pattern in signatures):
            self.add("low", "Possible debug or stack trace disclosure", path, "Body matched an error signature; content was not retained.", "Disable production debug output and verify manually.", "heuristic")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body):
            self.add("high", "Possible private key material", path, "A private-key header signature matched; no key was saved.", "Verify, remove public access and revoke any exposed key.", "signature")

    def inspect_html(self, path, url, body):
        parsed = PageParser()
        parsed.feed(body)
        base = urljoin(url, parsed.base_href) if parsed.base_href else url
        for tag, ref, integrity in parsed.resources:
            resource = urljoin(base, ref)
            p = urlsplit(resource)
            if self.scope[0] == "https" and p.scheme == "http":
                self.add("low", "Insecure resource reference", path, f"An HTML {tag} resource uses HTTP; browser upgrade/blocking was not tested.", "Use HTTPS resource URLs.")
            try:
                external = origin(resource) != self.scope
            except ValueError:
                external = False
            if tag in ("script", "link") and external and not integrity:
                self.add("info", "External asset without integrity metadata", path, "A third-party script/resource link lacks SRI; no third-party request was made.", "Consider SRI for fixed assets and review vendor trust; dynamic assets may need other controls.")
        for form in parsed.forms:
            target = urljoin(base, form["action"]) if form["action"] else url
            if form["password"] and (form["method"] == "get" or urlsplit(target).scheme != "https"):
                self.add("medium", "Password form uses GET or insecure transport", path, "Password input observed in a GET form or one targeting non-HTTPS transport.", "Submit credentials with POST over HTTPS.")
            try:
                external = origin(target) != self.scope
            except ValueError:
                external = True
            if external:
                self.add("info", "Form submits outside target origin", path, "Destination differs from the audited origin; no submission was made.", "Verify that the destination is intentional and trusted.")
            if form["method"] == "post" and not form["token_hint"]:
                self.add("info", "Form CSRF protection needs review", path, "No commonly named CSRF field observed. Other defenses may exist; CSRF is not confirmed.", "Verify server-side defenses on actual state changes.", "heuristic")
        if parsed.inline_handlers:
            self.add("info", "Inline event handlers observed", path, "Inline event attributes are present; this alone does not establish injection.", "Consider external event listeners when adopting a strict CSP.")
        self.routes[-1].update(forms=len(parsed.forms), password_forms=sum(f["password"] for f in parsed.forms),
                               upload_forms=sum(f["upload"] for f in parsed.forms))
        return [urljoin(base, ref) for ref in parsed.links], [urljoin(base, ref) for ref in parsed.scripts]

    def check_page(self, path):
        start, response_count = len(self.findings), len(self.responses)
        page = super().check_page(path)
        if not page:
            # The core inspects only successful pages. Inspect error signatures separately.
            self.record("Page headers/cookies/HTML", path, start, "Route inspection did not complete.", False)
            return [], []
        url, (status, headers, body) = page
        final_path = urlsplit(url).path or "/"
        self.routes.append(dict(path=path, final_path=final_path, status=status))
        if final_path != path:
            self.add("info", "Selected route redirected", path, "Inspected content belongs to a destination route; access to the original feature was not established.")
        self.check_disclosure(path, body)
        self.check_policies(path, headers, "text/html" in headers.get("Content-Type", "").lower())
        self.check_cookie_details(path, headers)
        try:
            links, scripts = self.inspect_html(path, url, body) if "text/html" in headers.get("Content-Type", "").lower() else ([], [])
        except ValueError:
            self.add("info", "Malformed HTML URL", path, "Invalid URL structure prevented complete HTML inspection; content omitted.")
            self.record("Page headers/cookies/HTML", path, start, "HTML URL parsing did not complete.", False)
            return [], []
        complete = len(self.responses) > response_count and not self.responses[-1]["truncated"] and headers.get("Content-Encoding", "identity").lower() in ("", "identity")
        self.record("Page headers/cookies/HTML", path, start, "Static inspection only; no browser execution or form submission.", complete)
        return links, scripts

    def check_cors(self, path, extended=False):
        start = len(self.findings)
        complete = True
        probe = f"https://audit-{uuid.uuid4().hex}.invalid"
        for probe_origin in ([probe, "null"] if extended else [probe]):
            result = self.fetch(urljoin(self.base, path), headers={"Origin": probe_origin})
            if not result or not 200 <= result[0] < 300:
                complete = False
                continue
            _, headers, _ = result
            allowed = headers.get("Access-Control-Allow-Origin", "").strip()
            credentials = headers.get("Access-Control-Allow-Credentials", "").lower().strip() == "true"
            if allowed == probe_origin:
                detail = ("Credentialed cross-origin reads are allowed by these headers; sensitive-data access requires browser/session verification."
                          if credentials else "An unfamiliar origin is accepted; may be intentional for public data.")
                self.add("medium" if credentials else "info", "CORS accepts an unfamiliar origin", path,
                         detail + (" Probe used null." if probe_origin == "null" else " Probe used a randomized origin."),
                         "Restrict origins for private APIs and verify with authenticated browser tests.", "policy_observation")
                vary = {s.strip().lower() for s in headers.get("Vary", "").split(",")}
                if "origin" not in vary and "*" not in vary:
                    self.add("info", "Origin-dependent CORS lacks Vary: Origin", path, "Potential cache inconsistency; cache behavior was not tested.", "Use Vary: Origin when responses differ by Origin.")
            elif allowed == "*":
                self.add("info", "Public CORS policy", path, "Wildcard CORS permits uncredentialed browser reads; often appropriate for public resources.")
        if extended:
            result = self.fetch(urljoin(self.base, path), headers={"Origin": probe, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}, method="OPTIONS", authenticated=False)
            complete &= bool(result and 200 <= result[0] < 300)
            if result and 200 <= result[0] < 300 and result[1].get("Access-Control-Allow-Origin", "").strip() in (probe, "*"):
                self.add("info", "CORS preflight accepts probe origin", path, "OPTIONS policy inspected; no POST or private-data read was attempted.")
        self.record("CORS", path, start, "Unfamiliar-origin GET" + (", null-origin GET and anonymous OPTIONS preflight." if extended else "."), complete)

    def check_methods(self, path):
        start = len(self.findings)
        result = self.fetch(urljoin(self.base, path), method="OPTIONS")
        if result:
            advertised = {m.strip().upper() for m in result[1].get("Allow", "").split(",")}
            review = sorted(advertised & {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"})
            if review:
                self.add("info", "Additional HTTP methods advertised", path, "Allow advertises " + ", ".join(review) + "; support and authorization were not tested.", "Verify that only required methods are enabled and protected.")
        self.record("HTTP method discovery", path, start, "OPTIONS only; absent Allow is inconclusive.", bool(result and result[0] < 500 and result[0] != 429))

    def check_reflection(self, path):
        start, response_count = len(self.findings), len(self.responses)
        super().check_reflection(path)
        complete = len(self.responses) > response_count and 200 <= self.responses[-1]["status"] < 300 and not self.responses[-1]["truncated"]
        self.record("Query reflection", path, start, "One inert codex_probe parameter; other inputs and DOM behavior were not tested.", complete)

    def check_exposures(self, extended=False):
        env = lambda b: len(re.findall(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", b)) >= 2 and bool(re.search(r"(?mi)^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|DATABASE_URL)[A-Z0-9_]*\s*=", b))
        checks = [("/.git/HEAD", "high", lambda b: bool(re.fullmatch(r"\s*(?:ref: refs/[^\s]+|[a-fA-F0-9]{40,64})\s*", b))),
                  ("/.git/config", "high", lambda b: "[core]" in b and "repositoryformatversion" in b), ("/.env", "high", env)]
        if extended:
            checks += [("/.env.local", "high", env), ("/.env.production", "high", env),
                       ("/.svn/entries", "medium", lambda b: "svn" in b.lower() and bool(re.search(r"(?m)^dir$", b))),
                       ("/server-status", "low", lambda b: "Apache Server Status" in b and "Server Version" in b),
                       ("/phpinfo.php", "medium", lambda b: "phpinfo()" in b and "PHP Version" in b)]
        baseline = self.fetch(urljoin(self.base, "/audit-missing-" + uuid.uuid4().hex))
        baseline_hash = digest(baseline[2]) if baseline and baseline[0] == 200 else None
        for path, level, matches in checks:
            if self.eligible(urljoin(self.base, path), discovered=False) is None:
                continue
            start = len(self.findings)
            result = self.fetch(urljoin(self.base, path))
            complete = bool(result and result[0] in (200, 401, 403, 404, 410))
            note = "Signature check of exact path; denial/not-found does not rule out other names."
            if result and result[0] == 200 and matches(result[2]):
                if baseline_hash == digest(result[2]):
                    note = "Signature also matches missing-path control; possible fallback, not confirmed exposure."
                    self.add("info", "Exposure signature also matches fallback", path, note, "Verify the resource manually.", "heuristic")
                else:
                    self.add(level, "Potentially sensitive resource publicly readable", path, "Resource signature matched; contents were not saved and secret usability was not verified.",
                             "Confirm exposure, restrict access and rotate any exposed credentials.", "signature")
            self.record("Exposure signatures", path, start, note, complete and not (result and self.responses[-1]["truncated"]))

    def discover(self):
        paths = []
        for path in ("/robots.txt", "/sitemap.xml"):
            if self.eligible(urljoin(self.base, path), discovered=False) is None:
                continue
            start = len(self.findings)
            result = self.fetch(urljoin(self.base, path))
            complete = bool(result and result[0] in (200, 401, 403, 404, 410))
            if result and result[0] == 200:
                body = result[2]
                if path.endswith(".xml"):
                    try:
                        if re.search(r"<!DOCTYPE|<!ENTITY", body, re.I):
                            raise ValueError("DTD not accepted")
                        root = ET.fromstring(body)
                        if root.tag.rsplit("}", 1)[-1] == "urlset":
                            paths.extend(urljoin(self.base, e.text.strip()) for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "loc" and e.text)
                        else:
                            self.discovery_notes.add("Sitemap indexes/nested sitemaps were not traversed.")
                    except (ET.ParseError, ValueError):
                        complete = False
                else:
                    for line in body.splitlines():
                        key, sep, value = line.partition(":")
                        value = value.split("#", 1)[0].strip()
                        if sep and key.strip().lower() == "allow" and value.startswith("/") and not any(c in value for c in "*$"):
                            try:
                                paths.append(urljoin(self.base, value))
                            except ValueError:
                                complete = False
            self.record("Discovery files", path, start, "Inventory hints only; robots.txt is not access control. Disallow paths were not probed.", complete and not (result and self.responses[-1]["truncated"]))
        return paths

    def inspect_script(self, path):
        start = len(self.findings)
        result = self.fetch(urljoin(self.base, path))
        if not result or result[0] != 200:
            self.record("Public JavaScript", path, start, "Script retrieval failed.", False)
            return
        _, headers, body = result
        mime = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if mime not in ("text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript"):
            self.record("Public JavaScript", path, start, "Response MIME type did not identify JavaScript.", False)
            return
        self.assets.append(dict(path=path, sha256_decoded_utf8=digest(body)))
        self.check_disclosure(path, body)
        patterns = {"DOM HTML insertion": r"\.innerHTML\s*=|\.outerHTML\s*=|\binsertAdjacentHTML\s*\(|\bdocument\.write\s*\(",
                    "Dynamic code execution": r"\beval\s*\(|\bnew\s+Function\s*\(",
                    "Browser token storage": r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:token|jwt|session|auth)"}
        for label, pattern in patterns.items():
            if re.search(pattern, body, re.I):
                self.add("info", label + " pattern to review", path, "Static pattern matched; comments, libraries and unreachable code can match. Data flow was not analyzed.",
                         "Trace attacker-controlled data and actual execution before classifying a vulnerability.", "heuristic")
        if re.search(r"[#@]\s*sourceMappingURL\s*=", body):
            self.add("info", "Source map reference observed", path, "Map content was not retrieved; source maps alone are not a vulnerability.", "Review published maps for sensitive source or secrets.")
        self.record("Public JavaScript", path, start, "Regex review only; no parsing, dependency resolution or browser execution.", not self.responses[-1]["truncated"])

    def run_pages(self, paths, crawl=False, max_pages=20, max_depth=2, max_assets=10, extended=False, reflection=False):
        queue = deque((path, 0) for path in dict.fromkeys(paths))
        queued = set(paths)
        done, scripts = set(), set()
        if crawl:
            for ref in self.discover():
                path = self.eligible(ref)
                if path and path not in queued and max_depth > 0 and len(queued) < max_pages * 10:
                    queue.append((path, 1))
                    queued.add(path)
        while queue and len(done) < max_pages and not self.halted and self.requests < self.max_requests:
            path, depth = queue.popleft()
            if path in done:
                continue
            done.add(path)
            if self.eligible(urljoin(self.base, path), discovered=False) is None:
                self.checks.append(dict(area="Selected route", path=path, status="not_tested", detail="Excluded by path prefix."))
                continue
            links, refs = self.check_page(path)
            self.check_cors(path, extended)
            if extended:
                self.check_methods(path)
            if reflection:
                self.check_reflection(path)
            for ref in refs:
                asset = self.eligible(ref)
                if asset:
                    scripts.add(asset)
            if crawl:
                for ref in links:
                    candidate = self.eligible(ref)
                    if candidate and candidate not in queued:
                        if depth < max_depth and len(queued) < max_pages * 10:
                            queue.append((candidate, depth + 1))
                            queued.add(candidate)
                        else:
                            self.discovery_notes.add("Crawl depth or discovery queue limit reached; some links were not inspected.")
        if queue:
            self.incomplete = True
            self.discovery_notes.add("Page/request limit or server stop condition left queued routes uninspected.")
        if extended:
            for path in sorted(scripts)[:max_assets]:
                if self.halted:
                    break
                self.inspect_script(path)
            if len(scripts) > max_assets:
                self.incomplete = True
                self.discovery_notes.add("JavaScript asset limit reached.")


def load_headers(path, target):
    if path is None:
        return {}
    if path.stat().st_size > 65536:
        raise ValueError("Header file must be smaller than 64 KiB.")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (ValueError, UnicodeError):
        raise ValueError("Header file contains invalid JSON; content omitted.") from None
    if not isinstance(data, dict) or not data:
        raise ValueError("Header file must be a nonempty JSON object.")
    for name, value in data.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise ValueError("Header file contains an invalid name or value; values omitted.")
        if name.lower() not in ("authorization", "cookie"):
            raise ValueError("Header file permits only Authorization and Cookie.")
    scheme, host, _ = origin(target)
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if scheme != "https" and not loopback:
        raise ValueError("Session headers require HTTPS except on loopback targets.")
    return data


def make_report(audit, mode):
    return dict(schema_version=2, tool_version=VERSION, target=audit.base,
                generated_at=datetime.now(timezone.utc).isoformat(), mode=mode,
                incomplete=audit.incomplete, requests=audit.requests,
                session_supplied=bool(audit.session_headers), session_validated=False, configuration=audit.configuration,
                summary=dict(findings_by_severity=dict(Counter(f["level"] for f in audit.findings)), checks_by_status=dict(Counter(c["status"] for c in audit.checks))),
                findings=audit.findings, checks=audit.checks, responses=audit.responses,
                routes=audit.routes, assets=audit.assets, tls=audit.tls, source=audit.source,
                discovery_notes=sorted(audit.discovery_notes),
                manual_review=[dict(area=area, status="not_tested", next_step=step) for area, step in MANUAL_REVIEW], references=REFERENCES,
                limitation="Bounded automated observations, not security certification. No browser execution, form submission, exploit validation or multi-role authorization testing. Supplied session validity is not established. No-finding means only that these checks found nothing in inspected data.")


def write_report(audit, out, mode):
    report = make_report(audit, mode)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    def cell(value):
        return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ").replace("`", "&#96;")
    md = ["# Website security assessment", "", f"Target: `{cell(audit.base)}`", "", f"Generated (UTC): {report['generated_at']}", "",
          f"Mode: {mode}; HTTP requests: {audit.requests}; incomplete: {audit.incomplete}", "",
          f"Session headers supplied: {bool(audit.session_headers)}; session validity not established.", "", report["limitation"], "",
          "## Coverage", "", "| Check | Path | Result | Scope |", "| --- | --- | --- | --- |"]
    for check in audit.checks:
        md.append("| " + " | ".join(cell(check[k]) for k in ("area", "path", "status", "detail")) + " |")
    if audit.tls:
        md += ["", "## TLS observation", "", f"Validated connection: {audit.tls['protocol']}; cipher: {audit.tls['cipher']}; expires: {audit.tls['certificate_expires_utc']}.", "", "One negotiated connection, not a protocol/cipher inventory."]
    if audit.source:
        md += ["", "## Local source inventory", "", f"Files inspected: {audit.source['files_inspected']}; dependency files: {cell(audit.source['dependency_files'])}; lockfiles: {cell(audit.source['lockfiles'])}; CI files: {cell(audit.source['ci_files'])}.", "", "Static patterns only; dependency vulnerabilities and CI behavior were not evaluated."]
    md += ["", "## Findings", ""]
    for finding in audit.findings:
        md += [f"### {finding['id']} — {finding['level'].upper()}: {finding['title']}", "", f"Path: `{cell(finding['path'])}`; confidence: {finding['confidence']}", "", finding["detail"], ""]
        if finding["remediation"]:
            md += ["Remediation: " + finding["remediation"], ""]
    if not audit.findings:
        md += ["No findings in the checks performed.", ""]
    md += ["## Discovery limitations", ""] + ["- " + note for note in sorted(audit.discovery_notes)]
    md += ["", "## Required manual and application-specific review", ""]
    md += [f"- **{area} — not tested:** {step}" for area, step in MANUAL_REVIEW]
    md += ["", "## References", ""] + [f"- [{key}]({url})" for key, url in REFERENCES.items()]
    (out / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Exact target origin")
    parser.add_argument("--comprehensive", action="store_true", help="Enable discovery, TLS, assets, exposure signatures, extended CORS, OPTIONS and inert reflection")
    parser.add_argument("--path", action="append", type=local_path, help="Selected route, repeatable; default /")
    parser.add_argument("--crawl", action="store_true", help="Discover query-free same-origin links and sitemap paths")
    parser.add_argument("--exclude-prefix", action="append", type=local_path, default=[], help="Exclude a path prefix from all HTTP checks")
    parser.add_argument("--check-exposures", action="store_true")
    parser.add_argument("--check-reflection", action="store_true")
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument("--skip-tls", action="store_true", help="Skip direct TLS handshake in comprehensive mode")
    parser.add_argument("--headers-file", type=Path, help="Private JSON file containing Authorization/Cookie for this origin")
    parser.add_argument("--source-dir", type=Path, help="Local website source for bounded static review")
    parser.add_argument("--max-source-files", type=int, default=500)
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--max-assets", type=int, default=10)
    parser.add_argument("--max-requests", type=int, default=160)
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between requests, minimum 0.25")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--out", type=Path, help="Fresh output directory; default timestamped under audit-results")
    args = parser.parse_args(argv)
    try:
        if not math.isfinite(args.timeout) or args.timeout <= 0 or not math.isfinite(args.delay) or args.delay < 0:
            raise ValueError("Use a positive finite timeout and finite nonnegative delay.")
        if any(v < 1 for v in (args.max_pages, args.max_requests, args.max_source_files)) or args.max_depth < 0 or args.max_assets < 0:
            raise ValueError("Page/request/source limits must be positive; depth/assets must be nonnegative.")
        p = urlsplit(args.url)
        if p.query or p.fragment or p.path not in ("", "/"):
            raise ValueError("Pass only the origin in URL; select routes with --path.")
        origin(args.url)
        headers = load_headers(args.headers_file, args.url)
        if args.source_dir is not None and not args.source_dir.is_dir():
            raise ValueError("Source directory does not exist.")
        out = args.out or Path("audit-results") / datetime.now(timezone.utc).strftime("audit-%Y%m%d-%H%M%S-%fZ")
        if out.exists() and not out.is_dir():
            raise ValueError("Output path must be a directory.")
        if any((out / name).exists() for name in ("report.json", "report.md")):
            raise ValueError("Output already contains a report; choose a fresh --out directory.")
        audit = Audit(args.url, args.delay, args.timeout, args.max_requests, headers, args.exclude_prefix)
        audit.configuration.update(selected_paths=args.path or ["/"], crawl=args.crawl or args.comprehensive,
                                   max_pages=args.max_pages, max_depth=args.max_depth, max_assets=args.max_assets,
                                   max_source_files=args.max_source_files, source_supplied=args.source_dir is not None,
                                   exposures=args.check_exposures or args.comprehensive,
                                   reflection=args.check_reflection or args.comprehensive)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if not args.skip_http or audit.scope[0] == "http":
        audit.check_http()
    else:
        audit.checks.append(dict(area="HTTP upgrade", path="/", status="not_tested", detail="Disabled with --skip-http."))
    if args.comprehensive and not args.skip_tls and not audit.halted:
        audit.check_tls()
    else:
        audit.checks.append(dict(area="TLS handshake", path="/", status="not_tested", detail="Not enabled or stopped by server backoff."))
    audit.run_pages(args.path or ["/"], crawl=args.crawl or args.comprehensive, max_pages=args.max_pages,
                    max_depth=args.max_depth, max_assets=args.max_assets, extended=args.comprehensive,
                    reflection=args.check_reflection or args.comprehensive)
    if args.check_exposures or args.comprehensive:
        audit.check_exposures(args.comprehensive)
    if args.source_dir is not None:
        from source_audit import review_source
        review_source(audit, args.source_dir, args.max_source_files, out, args.headers_file)
    else:
        audit.checks.append(dict(area="Local source patterns and inventory", path="source:/", status="not_tested", detail="No --source-dir supplied."))
    write_report(audit, out, "comprehensive" if args.comprehensive else "baseline")
    print(f"Finished: {audit.requests} HTTP requests, {len(audit.findings)} findings; incomplete={audit.incomplete}")
    print(f"Reports: {out.resolve()}")
    return 2 if audit.incomplete else (1 if any(f["level"] in ("medium", "high") for f in audit.findings) else 0)


if __name__ == "__main__":
    raise SystemExit(main())
