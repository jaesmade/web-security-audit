#!/usr/bin/env python3
"""Shared scoped HTTP client and baseline checks for website_audit.py."""
import argparse
import re
import ssl
import time
import uuid
from http.cookies import SimpleCookie, CookieError
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit, urlencode, urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler


class NoRedirect(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        # Let HTTPDefaultErrorHandler expose the response as HTTPError without
        # parsing Location. The default redirect handler can leak a response
        # when a malformed URL raises before redirect_request is reached.
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def origin(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError("Use an http(s) URL without embedded credentials.")
    if any(ord(c) < 33 for c in url) or "\\" in url:
        raise ValueError("URL contains whitespace, control characters or backslashes.")
    port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port.")
    return p.scheme.lower(), p.hostname.lower(), port


class Audit:
    def __init__(self, base, delay=0.5, timeout=10):
        self.scope = origin(base)
        p = urlsplit(base)
        self.base = urlunsplit((p.scheme, p.netloc, "/", "", ""))
        self.delay = max(0.25, delay)
        self.timeout = timeout
        self.last_request = 0.0
        self.requests = 0
        self.findings = []
        self.responses = []
        self.seen = set()
        self.incomplete = False
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))

    def add(self, level, title, path, detail):
        key = (title, path, detail)
        if key not in self.seen:
            self.seen.add(key)
            self.findings.append(dict(level=level, title=title, path=path, detail=detail))

    def fetch(self, url, headers=None, method="GET", allow_http=False):
        target = origin(url)
        permitted_http = allow_http and target == ("http", self.scope[1], 80)
        if target != self.scope and not permitted_http:
            raise ValueError("Request blocked: URL is outside the exact target origin.")
        pause = self.delay - (time.monotonic() - self.last_request)
        if pause > 0:
            time.sleep(pause)
        self.last_request = time.monotonic()
        self.requests += 1
        request_headers = {"User-Agent": "OwnerWebsiteAudit/2.0", "Accept-Encoding": "identity"}
        request_headers.update(headers or {})
        try:
            req = Request(url, headers=request_headers, method=method)
            try:
                response = self.opener.open(req, timeout=self.timeout)
            except HTTPError as exc:
                response = exc
            with response:
                body = response.read(262145)
                truncated = len(body) > 262144
                body = body[:262144].decode("utf-8", errors="replace")
                status = response.code
                response_headers = response.headers
            # Store metadata only: never cookies, response bodies or query values.
            path = urlsplit(url).path or "/"
            self.responses.append(dict(path=path, method=method, status=status, truncated=truncated))
            return status, response_headers, body
        except (URLError, TimeoutError, OSError, ValueError, HTTPException) as exc:
            self.incomplete = True
            # Exception messages can contain proxy credentials; keep only their types.
            reason = getattr(exc, "reason", exc)
            self.add("error", "Request failed", urlsplit(url).path or "/",
                     f"{type(reason).__name__}; inspect connectivity, DNS and certificate validity locally.")
            return None

    def page(self, path):
        current = urljoin(self.base, path)
        for _ in range(5):
            result = self.fetch(current)
            if not result:
                return None
            status, headers, body = result
            if status not in (301, 302, 303, 307, 308):
                return current, result
            location = headers.get("Location")
            if not location:
                self.incomplete = True
                self.add("info", "Redirect has no destination", path, "No final page was inspected.")
                return None
            next_url = urljoin(current, location)
            try:
                in_scope = origin(next_url) == self.scope
            except ValueError:
                in_scope = False
            if not in_scope:
                self.incomplete = True
                self.add("info", "Redirect leaves scope", path,
                         "Redirect was not followed. Rerun against the destination only if it is yours.")
                return None
            current = next_url
        self.incomplete = True
        self.add("info", "Redirect limit reached", path, "No final page was inspected.")
        return None

    def check_page(self, path):
        page = self.page(path)
        if not page:
            return
        url, (status, headers, body) = page
        if not 200 <= status < 300:
            self.incomplete = True
            self.add("info", "Page was not successful", path,
                     f"HTTP {status}; application checks for this path were skipped.")
            return
        html_page = "text/html" in headers.get("Content-Type", "").lower()
        if self.scope[0] == "https" and not headers.get("Strict-Transport-Security"):
            self.add("low", "HSTS header absent", path, "Consider HSTS after confirming HTTPS works for the intended host scope.")
        if html_page:
            csp = headers.get("Content-Security-Policy", "")
            if not csp:
                self.add("low", "Enforced CSP absent", path,
                         "A restrictive Content-Security-Policy can reduce script-injection impact; absence does not establish XSS.")
            if not headers.get("X-Frame-Options") and not re.search(r"(?:^|;)\s*frame-ancestors\s", csp, re.I):
                self.add("low", "Framing protection absent", path,
                         "If embedding is unnecessary, consider CSP frame-ancestors. Exploitability depends on page functionality.")
            if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
                self.add("low", "MIME sniffing protection absent", path, "Consider X-Content-Type-Options: nosniff.")
            if not headers.get("Referrer-Policy"):
                self.add("info", "Explicit referrer policy absent", path,
                         "Browsers apply defaults; consider an explicit policy for predictable referrer handling.")
            if self.scope[0] == "https" and re.search(r'''(?:src|href)\s*=\s*["']http://''', body, re.I):
                self.add("info", "HTTP resource or link found", path,
                         "Inspect HTTP references manually; ordinary hyperlinks are not necessarily mixed content.")
        for raw in headers.get_all("Set-Cookie", []):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except CookieError:
                continue
            for name, morsel in cookie.items():
                session_like = bool(re.search(r"session|auth|token|jwt|sid", name, re.I))
                missing = []
                if not morsel["secure"]:
                    missing.append("Secure")
                if session_like and not morsel["httponly"]:
                    missing.append("HttpOnly")
                if not morsel["samesite"]:
                    missing.append("SameSite")
                if missing:
                    self.add("low" if session_like else "info", "Cookie flags to review", path,
                             "A cookie lacks " + ", ".join(missing) + ". Cookie names/values are omitted; intended use must be reviewed.")
        for header in ("Server", "X-Powered-By"):
            if headers.get(header):
                self.add("info", "Technology header present", path,
                         f"{header} discloses implementation information; this alone is not a vulnerability.")
        return page

    def check_http(self):
        if self.scope[0] != "https":
            self.add("medium", "Target uses plain HTTP", "/", "Use HTTPS before sending credentials or private data.")
            return
        if self.scope[2] != 443:
            return
        host = self.scope[1]
        host = f"[{host}]" if ":" in host else host
        result = self.fetch(f"http://{host}/", allow_http=True)
        if result:
            status, headers, _ = result
            try:
                destination = urljoin(f"http://{host}/", headers.get("Location", ""))
                correct = origin(destination) == self.scope
            except ValueError:
                correct = False
            if status in (301, 302, 303, 307, 308) and correct:
                return
            self.add("low", "HTTP upgrade needs review", "/",
                     "The HTTP root did not redirect directly to the scoped HTTPS origin; no redirect was followed.")

    def check_cors(self, path):
        probe_origin = f"https://audit-{uuid.uuid4().hex}.invalid"
        result = self.fetch(urljoin(self.base, path), headers={"Origin": probe_origin})
        if not result:
            return
        status, headers, _ = result
        if not 200 <= status < 300:
            return
        allowed = headers.get("Access-Control-Allow-Origin", "").strip()
        credentials = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if allowed == probe_origin:
            self.add("medium" if credentials else "info", "CORS reflects an unfamiliar origin", path,
                     "Credentialed cross-origin reads are enabled; verify whether sensitive authenticated data is exposed. No credentials were sent."
                     if credentials else "May be intentional for a public API; review the origin policy. No private data access was demonstrated.")
        elif allowed == "*":
            self.add("info", "Public CORS policy", path,
                     "Wildcard CORS allows uncredentialed browser reads. This is often intentional for public resources.")

    def check_exposures(self):
        checks = [
            ("/.git/HEAD", lambda b: bool(re.fullmatch(r"\s*(?:ref: refs/[^\s]+|[a-fA-F0-9]{40,64})\s*", b))),
            ("/.git/config", lambda b: "[core]" in b and "repositoryformatversion" in b),
            ("/.env", lambda b: len(re.findall(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", b)) >= 2
             and bool(re.search(r"(?mi)^\s*[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|DATABASE_URL)[A-Z0-9_]*\s*=", b))),
        ]
        for path, matches in checks:
            result = self.fetch(urljoin(self.base, path))
            if result and result[0] == 200 and matches(result[2]):
                self.add("high", "Potentially sensitive file is publicly readable", path,
                         "Response matched a configuration/repository signature. Contents were not saved. Confirm exposure and remove public access; rotate any exposed secrets.")

    def check_reflection(self, path):
        canary = "<audit_" + uuid.uuid4().hex + ">"
        url = urljoin(self.base, path) + "?" + urlencode({"codex_probe": canary})
        result = self.fetch(url)
        if result and 200 <= result[0] < 300 and "text/html" in result[1].get("Content-Type", "").lower() and canary in result[2]:
            self.add("info", "Unescaped canary reflected in HTML", path,
                     "A harmless marker appeared unchanged. Review its HTML context; no JavaScript ran and XSS is not confirmed.")


def local_path(value):
    p = urlsplit(value)
    if not value.startswith("/") or value.startswith("//") or p.scheme or p.netloc or p.query or p.fragment or "\\" in value or any(ord(c) < 33 for c in value):
        raise argparse.ArgumentTypeError("Provide an absolute local path, e.g. / or /api/status, without a query or fragment.")
    return value
