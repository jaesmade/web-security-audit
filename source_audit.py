"""Bounded, offline source inventory and security-pattern review; not SAST."""
from collections import deque
import os
from pathlib import Path
import re

SKIP_DIRS = {".git", ".svn", "node_modules", "vendor", ".venv", "venv", "__pycache__",
             "dist", "build", "coverage", ".next", ".nuxt", "audit-results"}
TEXT_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".php", ".rb", ".go",
                 ".java", ".cs", ".html", ".htm", ".json", ".yaml", ".yml", ".toml", ".ini",
                 ".conf", ".config", ".xml", ".sh", ".ps1", ".sql", ".vue", ".svelte", ".tf"}
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "Pipfile", "composer.json",
             "Gemfile", "go.mod", "pom.xml", "Cargo.toml"}
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock",
             "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock"}


def reparse(path):
    """Skip Windows junctions as well as symlinks, including on Python 3.10."""
    return path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)


def review_source(audit, root, max_files=500, output=None, headers_file=None):
    root = root.resolve()
    excluded = {p.resolve() for p in (output, headers_file) if p is not None}
    inventory = dict(files_inspected=0, dependency_files=[], lockfiles=[], ci_files=[], skipped_files=0,
                     scope="UTF-8 text up to 1 MiB each; generated/vendor directories and reparse points excluded. Static patterns only; no advisory lookup or data-flow analysis.")
    start = len(audit.findings)
    complete = True
    queue = deque([root])
    visited = 0
    while queue and inventory["files_inspected"] < max_files and visited < 10000:
        directory = queue.popleft()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > 10000:
                        complete = False
                        break
                    path = Path(entry.path)
                    if reparse(path) or path.resolve() in excluded:
                        continue
                    if not path.resolve().is_relative_to(root):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.lower() not in SKIP_DIRS:
                            queue.append(path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    name = entry.name
                    relative = path.relative_to(root).as_posix()
                    if name in MANIFESTS or name.endswith(".csproj"):
                        inventory["dependency_files"].append(relative)
                    if name in LOCKFILES:
                        inventory["lockfiles"].append(relative)
                    if relative.startswith(".github/workflows/") or name in (".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"):
                        inventory["ci_files"].append(relative)
                    if name in LOCKFILES:
                        # Inventory lockfiles without parsing huge generated trees.
                        continue
                    if path.suffix.lower() not in TEXT_SUFFIXES and name not in MANIFESTS and not name.startswith(".env"):
                        continue
                    if inventory["files_inspected"] >= max_files:
                        complete = False
                        break
                    if path.stat().st_size > 1048576:
                        inventory["skipped_files"] += 1
                        complete = False
                        continue
                    try:
                        body = path.read_bytes().decode("utf-8-sig")
                    except UnicodeError:
                        inventory["skipped_files"] += 1
                        complete = False
                        continue
                    if "\x00" in body:
                        inventory["skipped_files"] += 1
                        continue
                    inventory["files_inspected"] += 1
                    location = "source:" + relative
                    rules = [
                        ("high", "Possible private key in source", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                         "Verify whether the key is real; remove it from source/history and rotate it."),
                        ("low", "Production debug setting to review", r"(?m)^\s*(?:DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true)\b",
                         "Confirm production debug mode is disabled; development settings may be intentional."),
                    ]
                    if path.suffix.lower() in {".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}:
                        rules += [("info", "Source DOM insertion pattern to review", r"\.innerHTML\s*=|dangerouslySetInnerHTML|\bv-html\s*=",
                                   "Trace input sources and sanitization; static pattern matches do not establish XSS.")]
                    if path.suffix.lower() == ".py":
                        rules += [("info", "Unsafe deserialization pattern to review", r"\bpickle\.loads?\s*\(|\byaml\.load\s*\(",
                                   "Verify input trust and loader configuration; no exploitability was established.")]
                    for level, title, pattern, remedy in rules:
                        match = re.search(pattern, body)
                        if match:
                            line = body.count("\n", 0, match.start()) + 1
                            audit.add(level, title, location, f"Static signature matched at line {line}; source content was omitted.", remedy, "heuristic")
                    # Do not echo candidate values or source snippets into evidence.
                    if not any(marker in name.lower() for marker in ("example", "sample", "template")):
                        assignment = re.compile(r'''(?mi)^\s*["']?(?:[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_TOKEN)[A-Z0-9_]*)["']?\s*[:=]\s*["']?([^\s"'#,;]{16,})''')
                        for match in assignment.finditer(body):
                            value = match[1]
                            if re.search(r"example|placeholder|changeme|your[_-]|process\.|environ|\$|\{|\}|<|>|getenv|config\(", value, re.I):
                                continue
                            line = body.count("\n", 0, match.start()) + 1
                            audit.add("medium", "Potential hardcoded credential", location,
                                      f"Credential-like assignment at line {line}; name and value omitted. Examples can match.",
                                      "Verify the candidate, move real secrets to secret storage and rotate exposed values.", "heuristic")
                            break
        except OSError as exc:
            complete = False
            audit.add("error", "Source path could not be inspected", "source:/", type(exc).__name__ + "; path/error details omitted.")
    if queue or visited >= 10000:
        complete = False
    if not complete:
        audit.discovery_notes.add("Local source inspection was limited by budgets, file size, encoding or read failures.")
    for key in ("dependency_files", "lockfiles", "ci_files"):
        inventory[key].sort()
    audit.source = inventory
    audit.record("Local source patterns and inventory", "source:/", start, inventory["scope"], complete)
