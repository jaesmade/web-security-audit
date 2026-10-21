# Website security auditor

## Explanation

This project helps website owners and authorized testers check a website for common security weaknesses and configuration gaps. It collects bounded HTTP observations, reviews selected page and script content, and produces Markdown and JSON reports with findings, suggested remediation and the checks that still need manual work.

There are two main modes. **Baseline mode** checks selected routes, response headers, cookie flags, HTTP upgrade behavior and CORS. **Comprehensive mode** adds bounded discovery, more probes, public JavaScript inspection and a separate TLS handshake. Either mode can also review local website source when you provide `--source-dir`.

The Python auditor requires **Python 3.10 or later** and uses only the standard library; no pip packages are required. Keep `website_audit.py`, `audit_core.py` and `source_audit.py` in the same folder. Nmap is required only for the optional PowerShell runner.

## Disclaimer

This project is intended for defensive security assessment and education.

- **Authorized use only.** Test only systems you own or have explicit permission to assess. Agree on the hostnames, routes, accounts, methods and request limits before testing. Public accessibility, a working login or possession of credentials does not by itself authorize a security assessment. Respect applicable laws, service-provider rules and the owner's agreed scope, including restrictions on shared hosting and CDN infrastructure.
- **Limited assurance.** Automated checks can produce false positives and miss vulnerabilities. `--comprehensive` describes the broader automated mode; it does not mean a complete penetration test, compliance assessment or security certification. A clean report does not establish that a website is secure. Verify findings in context before acting on them.
- **Operational effects.** Requests can trigger monitoring, rate limits or application behavior. Even GET endpoints can change state in some applications, especially with a supplied session. Review the target workflows, use dedicated test accounts and prefer a staging environment where practical.
- **No warranty.** The tool and its reports are provided "as is," without guarantees of accuracy, completeness, suitability or uninterrupted operation. You are responsible for selecting the scope, configuring and running the tool, verifying results and deciding how to apply remediation.
- **Protect sensitive material.** Before pushing this repository or sharing results, review `audit-results/`, downloaded page snapshots, raw Nmap output and any session files. Remove or redact credentials, cookies, personal data, internal paths and confidential findings. The Python report's redaction does not sanitize every file in this repository, and `.gitignore` does not remove files already tracked by Git.
- **Responsible disclosure.** Share findings privately with the system owner through an agreed reporting channel. Obtain permission before publishing target-specific evidence or vulnerability details. Domain names, product names and reports included in this project do not imply affiliation, endorsement or authorization to test those systems.

## Summary of how to use

1. Download or clone this repository, open PowerShell in its folder, and check that `python --version` reports Python 3.10 or later.
2. Replace `https://your-site.example` with the exact origin of a website you are authorized to assess. Run the broader live-website checks:

```powershell
python .\website_audit.py https://your-site.example --comprehensive
```

3. If you also have the actual website's source code on your computer, add its folder:

```powershell
python .\website_audit.py https://your-site.example --comprehensive --source-dir "D:\Projects\your-website"
```

4. Open the generated `report.md` for the readable results or `report.json` for structured results. The terminal prints the output folder, normally a new timestamped directory under `audit-results/`. Review findings, incomplete checks and the manual-review list before deciding what to fix.

**You run one Python command.** `website_audit.py` automatically imports `audit_core.py`. It imports and uses `source_audit.py` only when you supply `--source-dir`. Do not run either helper separately. `--comprehensive` without `--source-dir` checks the live website without inspecting local source files. The Nmap runner is separate and is never started automatically by this command.

For a smaller baseline check, omit `--comprehensive`:

```powershell
python .\website_audit.py https://your-site.example
```

Replace all example URLs and paths with yours. A PowerShell backtick at the end of a line continues the same command onto the next line; a command written entirely on one line does not need a trailing backtick.

## Detailed summary

### Each project file

| File or folder | What it does | How it is used |
| --- | --- | --- |
| `website_audit.py` | Main entry point. Reads command options, coordinates discovery and security checks, applies request limits, and writes the reports. | Run this file for both baseline and comprehensive audits. It loads the helper modules automatically. |
| `audit_core.py` | Shared HTTP client and baseline checks. Handles scoped requests, certificate validation through the HTTP client, response metadata, headers, cookie flags and the inert reflection probe. | Imported automatically by `website_audit.py`. Keep it beside the main script; no separate command is needed. |
| `source_audit.py` | Offline inspection of the supplied website source folder. Looks for selected credential, private-key, debug and dangerous-code patterns; inventories dependency manifests, lockfiles and CI files. | Used only with `--source-dir`. It does not install dependencies, run the website, execute CI or query vulnerability advisories. |
| `run-nmap-http-audit.ps1` | Optional Nmap follow-up for HTTP metadata and the presented certificate, using four selected scripts on TCP 443. Saves its own evidence separately. | Run manually with `-TargetHost`. Use `-PlanOnly` to inspect the planned arguments without scanning. Requires Nmap for an actual scan. |
| `README.md` | Explanation, disclaimer, usage examples, option descriptions and assessment limitations. | Start here when using or sharing the project. |
| `.gitignore` | Excludes Python caches, a local virtual environment and common private session-file names from new Git tracking. | Used by Git. It does not remove already-tracked files and does not automatically exclude every audit result. |
| `audit-results/` | Saved assessments and evidence. New Python runs create `report.md` and `report.json`; older folders may also contain snapshots or Nmap output. | Generated output, not required to run the auditor. Review and redact it before publishing. Old reports do not describe the current deployment or prove it secure. |
| `__pycache__/` | Python's generated bytecode cache. | Created automatically; not required to distribute and excluded by `.gitignore`. |

### Selecting routes and setting scope

Include known routes, exclude sensitive workflows, and optionally review the actual local website source:

```powershell
python .\website_audit.py https://your-site.example --comprehensive `
  --path / --path /login --path /api/status `
  --exclude-prefix /logout --exclude-prefix /account/delete `
  --source-dir "D:\Projects\your-website" `
  --max-pages 30 --max-depth 3 --max-assets 15 --max-requests 250
```

Paths must start with `/` and contain no query or fragment. Repeated `--path` values supplement discovery; `/` is the default only when none are supplied. Paths returning errors or redirecting to login do not establish access to the intended feature. Explicitly select unlinked API routes: this tool cannot discover an entire backend from homepage links.

### Each command option

| Option | Purpose | Default or important behavior |
| --- | --- | --- |
| `url` | Required website origin, such as `https://your-site.example`. | Include the scheme and hostname, plus a port if needed. Select routes with `--path`; do not put credentials, query parameters or a route in this argument. |
| `--comprehensive` | Enables discovery, a TLS handshake, public-script review, extended CORS, OPTIONS, extended exposure probes and an inert reflection probe. | Off. Local source review still requires `--source-dir`. |
| `--path /route` | Selects a route explicitly; repeat for multiple routes. | `/` when no paths are provided. Selected routes count toward the page and request budgets. |
| `--crawl` | Discovers query-free same-origin links and selected discovery-file entries. | Off in baseline mode; enabled by `--comprehensive`. |
| `--exclude-prefix /route` | Blocks HTTP requests whose paths begin with this prefix, including redirects and probes. | No extra exclusions; repeat to add prefixes. This is a prefix match, so `/admin` also matches `/administrator`. |
| `--check-exposures` | Adds checks for `/.git/HEAD`, `/.git/config` and `/.env`, plus a missing-path control. | Off in baseline mode. Comprehensive mode includes these and additional signatures. |
| `--check-reflection` | Sends an inert marker in the `codex_probe` query parameter. | Off in baseline mode; enabled by `--comprehensive`. A reflected marker does not establish executable XSS. |
| `--skip-http` | Omits the separate HTTP-port-80 upgrade request. | Upgrade request enabled for standard-port HTTPS targets. A plain HTTP target still receives a transport finding. |
| `--skip-tls` | Omits the separate direct TLS handshake. | That handshake is enabled by `--comprehensive`; normal HTTPS client certificate validation still applies. |
| `--headers-file PATH` | Loads an existing test session from a private JSON file containing `Authorization` and/or `Cookie`. | No supplied session. Session validity and cross-user permissions are not established. |
| `--source-dir PATH` | Adds offline pattern review and inventory of the actual website source directory. | No local source review. Point this at the website project, not this auditor's folder, unless reviewing the auditor itself. |
| `--max-source-files N` | Caps local text files inspected. | `500`; positive integer. |
| `--max-pages N` | Caps selected and discovered pages inspected. | `20`; positive integer. |
| `--max-depth N` | Limits crawl depth from selected routes. | `2`; nonnegative integer. |
| `--max-assets N` | Caps same-origin public JavaScript files reviewed in comprehensive mode. | `10`; `0` disables that asset review. |
| `--max-requests N` | Caps HTTP requests across redirects, discovery and probes. | `160`; positive integer. The separate TLS handshake is not an HTTP request. |
| `--delay SECONDS` | Sets the pause between requests. | `0.5`; effective minimum `0.25`. |
| `--timeout SECONDS` | Sets the network operation timeout. | `10`; positive finite value. It is not a total deadline for the entire assessment. |
| `--out PATH` | Selects an output directory. | A new UTC-timestamped directory under `audit-results/`. Existing reports are not overwritten. |
| `-h`, `--help` | Displays the command-line usage and options. | Prints help without auditing a target. |

### Each audit area

| Area | Automated coverage | Practical limit |
| --- | --- | --- |
| Transport | HTTP upgrade; client certificate validation; negotiated TLS version/cipher and certificate expiry | One direct TLS connection, not supported-protocol/cipher enumeration; HTTP may use system proxies while TLS connects directly |
| Headers | HSTS presence/max-age, CSP presence and selected permissive directives, framing, MIME sniffing, referrer policy, technology headers | Static policy heuristics; multiple CSP policies require manual review; no browser validation |
| Cookies | Secure/HttpOnly/SameSite review, SameSite=None + Secure, __Host-/__Secure- attributes | Names indicate possible session use; intended semantics and session lifecycle need verification; final successful page responses only |
| CORS | Randomized unfamiliar origin, null origin and POST preflight headers | No POST is sent; headers alone do not prove readable sensitive data |
| HTML | Forms/password fields/uploads inventory, insecure resources, third-party assets without integrity metadata, inline handlers | No forms submitted; CSRF field heuristics cannot prove missing protection; no DOM execution |
| Discovery | Same-origin, query-free links; robots Allow entries and sitemap URL entries | Does not probe robots Disallow entries, traverse sitemap indexes, execute JS routing or crawl other origins |
| Public scripts | Same-origin external scripts; DOM insertion, dynamic evaluation, token-storage patterns, map references, private-key signatures | Regex patterns are review leads; comments/minified code can match; no import graph, inline-script review or source-map retrieval |
| Exposures | /.git/HEAD, /.git/config, /.env, /.env.local, /.env.production, /.svn/entries, /server-status, /phpinfo.php | Signature-based exact-path checks with a missing-path fallback control; no backup/archive enumeration or secret usability test |
| HTTP methods | OPTIONS Allow header | Advertised methods are informational; no PUT/PATCH/DELETE/TRACE/CONNECT sent |
| Reflection/errors | One inert HTML marker in codex_probe; selected stack-trace/debug signatures including unsuccessful responses | No executable XSS, SQL injection, command injection or exploit validation |
| Local source | Credential/private-key/debug/selected dangerous API patterns; manifest, lockfile and CI file inventory | Optional --source-dir; bounded UTF-8 files only; no dependency advisory lookup, full SAST, CI execution or data-flow analysis |

The policy checks draw on [OWASP HTTP header guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [CSP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) and [CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html). These references guide individual observations; the tool does not claim full OWASP testing-guide or ASVS coverage.

### Using a supplied session

For pages requiring an existing test session, create a private JSON file outside the website repository:

```json
{
  "Authorization": "Bearer REPLACE_WITH_TEST_SESSION"
}
```

`Cookie` is also accepted. Other custom headers are rejected.

```powershell
python .\website_audit.py https://your-site.example --comprehensive `
  --headers-file "D:\Private\session-headers.private.json" `
  --path /dashboard --exclude-prefix /logout
```

Headers are sent only to the exact target origin, never to the HTTP-upgrade endpoint. Non-loopback sessions require HTTPS. Responses do not update a cookie jar. Session validity is **not established**: check the route/status results for login redirects or access errors. Run anonymous and role-specific assessments separately, using fresh outputs, and manually compare object permissions and state-changing operations. A supplied session does not test authorization boundaries.

Reports omit request-header values, cookie names/values, response bodies, query values and candidate secret snippets. Paths and source filenames are retained, so avoid credentials in path segments or filenames. Protect session files; `.gitignore` covers `session-headers*.json` and `*.private.json`. Local source scanning excludes the supplied header file and current output directory.

### Local source review

`--source-dir` is an optional addition to either audit mode. The source folder is read locally; its contents are not uploaded to the target. Source findings identify a relative filename and line number without copying candidate secret values or source snippets into the report.

The review can flag selected private-key signatures, credential-like assignments, debug settings and certain code patterns. These are leads for manual verification: comments, fixtures and development settings can match. Dependency manifests, lockfiles and CI files are inventoried, but no dependency-vulnerability database is consulted and no build or package command is executed.

Generated/vendor directories, `audit-results/`, the current output directory, the supplied session file, symlinks and Windows junctions are excluded. Text inspection is limited to selected UTF-8 file types up to 1 MiB each, the configured file count and a 10,000-entry traversal cap. Source budget, encoding, file-size and read failures can leave this part of the assessment incomplete.

### Bounds and scope

- Defaults: 20 pages, depth 2, 10 public scripts, 160 HTTP requests, 500 local source files, 10-second network operation timeout, 0.5-second pacing (minimum 0.25).
- Requests are sequential with no automatic retries. The request budget includes redirects, discovery, OPTIONS and probes. TLS uses one separately reported connection.
- HTTP follows only the exact scheme, hostname and port. The upgrade check makes one anonymous request to port 80 on the same hostname, only for a standard-port HTTPS target; `--skip-http` omits that request. Plain HTTP targets still receive a transport finding.
- `--skip-tls` disables the separate comprehensive-mode handshake. Browser certificate behavior and legacy TLS support are not assessed.
- HTTP 429 or HTTP 503 with Retry-After stops further HTTP requests. Partial checks, truncated bodies and budget-limited queued pages mark the assessment incomplete.
- Each body is limited to 256 KiB; unsupported content encodings are not decompressed. There are no third-party asset requests, form submissions or write-method probes.
- Discovered query-bearing links and common action paths such as logout/delete are skipped. `--exclude-prefix` blocks all matching HTTP request paths, including redirects and probes. Crawling still makes GET requests; GET endpoints must be reviewed for application-specific side effects before use with a privileged session.
- Only a bounded set of same-origin URLs is discovered; the report records depth, queue and asset limits. `incomplete: false` means configured checks completed within their stated scope, not that the whole application was assessed.
- Source scanning skips vendor/generated directories, audit-results, symlinks and Windows junctions; inspects UTF-8 text up to 1 MiB each; and has a 10,000-entry traversal cap. Large/unreadable text files and source budget limits are reported as partial. Lockfiles are inventoried, not parsed for vulnerabilities.

### Each output and result

Default output is a fresh UTC-timestamped directory under `audit-results`. Use `--out .\audit-results\your-run` to select a fresh directory; existing reports are not overwritten. Historical reports in this workspace are preserved and do not represent a scan with version 2.

`report.json` (schema version 2) and `report.md` contain findings, remediation, confidence labels, per-check coverage, route destinations, response status metadata, discovered form counts, script hashes, optional TLS/source inventories and outstanding manual tests. `requests`, `incomplete`, `findings` and `responses` remain available to existing JSON consumers.

| Output or field | How to read it |
| --- | --- |
| `report.md` | Human-readable coverage, findings, remediation, inventories and outstanding manual work. Start here when reviewing a run. |
| `report.json` | Structured record for processing or comparing runs; includes configuration, request/status metadata, routes, findings and inventories. |
| `findings` | Observations labeled by severity and confidence. Read the detail and remediation; a heuristic match is not a verified exploit. |
| `checks` | Per-check coverage using the statuses described below. |
| `responses` and `routes` | HTTP method/status records and selected-to-final route information. A login redirect does not prove the intended feature was assessed. |
| `tls` | Metadata from one validated handshake, if completed; does not enumerate all supported protocols or ciphers. |
| `source` | Local source inventory, if requested, with counts and identified dependency/CI filenames. |
| `incomplete` | Indicates that some requested checks could not finish within their stated scope. `false` is not a security certification. |
| `manual_review` | Application-specific work that the automated run did not perform. |

Coverage uses `no_finding` (no finding in that check's inspected data), `finding` (at least one observation added), `incomplete` (the check did not fully finish) or `not_tested` (not enabled, excluded or unavailable). An informational observation can produce `finding`; it does not necessarily represent an exploitable vulnerability. Confidence distinguishes direct observations from signatures, policy observations and heuristic leads. No security score is assigned.

The process exit code summarizes the run:

- `0`: completed without medium/high findings; low/info findings can still require work.
- `1`: completed with at least one medium/high finding.
- `2`: incomplete assessment or invalid arguments; inspect findings even when the run is incomplete.

### Manual work after an automated audit

Every report lists untested work: authentication/recovery/MFA, cross-role authorization and IDOR, injection and browser behavior, CSRF and business logic, uploads/SSRF, API/abuse controls, dependency advisories/CI, infrastructure/deployment access and full TLS configuration. Use the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) to design tests for the actual application. Preserve evidence, fix verified problems, then retest the changed deployment with fresh outputs.

### Optional baseline probes

The original entry point and optional probes remain available:

```powershell
python .\website_audit.py https://your-site.example --check-exposures --check-reflection
```

This checks selected routes without crawling or the extra TLS handshake. Exposure checking now also requests a missing-path control to reduce fallback-page false positives.

### Optional Nmap follow-up

The runner now requires a hostname instead of using a fixed website. It keeps the four-script allowlist and TCP 443 scope. Nmap must be installed for execution.

```powershell
.\run-nmap-http-audit.ps1 -TargetHost your-site.example -PlanOnly
.\run-nmap-http-audit.ps1 -TargetHost your-site.example
```

`-PlanOnly` prints arguments without creating files or contacting the target. `-OutDirectory` selects a new output directory. Host input rejects URL syntax, ranges and script-argument injection. The runner accepts DNS names/IPv4, not IPv6 literals. Nmap's HTTP scripts can follow redirects using their own rules, so review deployment redirects before using this separate runner. It does not send the Python auditor's supplied session. Raw Nmap evidence can include server headers and cookie values; handle it accordingly. The Python report is not automatically merged with Nmap results. See the [Nmap HTTP-title documentation](https://nmap.org/nsedoc/scripts/http-title.html) for redirect behavior.

| Nmap script | What it collects |
| --- | --- |
| `http-title` | The title of the returned page; can help identify the responding application. |
| `http-headers` | HTTP response headers for review. |
| `http-security-headers` | Selected security-header observations; omitted entries do not constitute a comprehensive pass/fail result. |
| `ssl-cert` | Fields from the presented certificate; retrieval alone does not establish full TLS configuration security. |

The runner writes its own `scan.nmap`, `scan.xml`, `scan.gnmap`, `scope.txt` and `invocation.json` files in a fresh output directory. It scans TCP 443 only and does not perform a full port scan or attempt application exploitation.

### Local verification

Check that the command starts and the three Python files compile:

```powershell
python .\website_audit.py --help
python -m py_compile website_audit.py audit_core.py source_audit.py
```

These commands display usage and check Python syntax without scanning a website. They do not validate audit accuracy or replace integration tests. The compile command may create `__pycache__/`, which is generated output and can be omitted when distributing the project.
