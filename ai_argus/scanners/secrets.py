"""Secrets scanner — detects hardcoded credentials in a local path.

Fully offline. Walks a directory target (or the CWD) and applies high-precision
regex signatures. Reliability rule honored: every match becomes evidence with a
redacted snippet; no raw secret is ever persisted.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

from .base import Scanner, ScannerResult, register
from ..core.context import ScanContext
from ..models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding,
    Impact, Owner, Remediation, Severity,
)

# label, pattern, severity, value_group, needs_entropy
SIGNATURES: List[Tuple[str, re.Pattern, Severity, int, bool]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, 0, False),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL, 0, False),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), Severity.HIGH, 0, False),
    ("Generic API Key", re.compile(r"(?i)(?:api[_-]?key|secret)\s*[:=]\s*['\"]([0-9a-zA-Z]{16,})['\"]"), Severity.HIGH, 1, True),
    ("Bearer Token", re.compile(r"(?i)bearer\s+([A-Za-z0-9._\-]{20,})"), Severity.MEDIUM, 1, True),
    ("Password Assignment", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), Severity.MEDIUM, 1, True),
]

# Directories never worth scanning for secrets (pruned during the walk).
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor",
             ".idea", ".vscode", "target", ".gradle", "coverage", ".next"}
# Path segments indicating sample/test/doc content -- common false-positive sources.
NOISE_PARTS = {"test", "tests", "__tests__", "testdata", "spec", "specs",
               "doc", "docs", "example", "examples", "sample", "samples",
               "fixture", "fixtures", "mock", "mocks", "__mocks__", "demo"}
# Only inspect likely code/config files (avoids reading binaries/data).
SCAN_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php",
             ".cs", ".cpp", ".c", ".h", ".rs", ".kt", ".scala", ".swift", ".sh",
             ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".json", ".toml", ".ini",
             ".cfg", ".conf", ".config", ".properties", ".xml", ".env", ".tf",
             ".tfvars", ".gradle", ".txt"}
SCAN_FILENAMES = {".env", "dockerfile", "makefile", ".npmrc", ".pypirc"}
MAX_FILE_BYTES = 1_000_000
ENTROPY_MIN = 3.0  # bits/char; below this a matched value is likely a placeholder

# Anchored placeholder/template values that are not real credentials.
_PLACEHOLDER_RE = re.compile(
    r"^(?:changeme|change_me|password|passwd|pwd|secret|api[_-]?key|token|"
    r"example|examples|test|testing|sample|dummy|placeholder|redacted|"
    r"none|null|true|false|x{3,}|\*{3,}|\.{3,}|"
    r"your[_-]?\w+|my[_-]?\w+|some[_-]?\w+|"
    r"<[^>]*>|\{\{.*\}\}|\{.*\}|\$\{.*\}|\$\(.*\)|"
    r"env\(.*\)|process\.env.*|os\.environ.*)$",
    re.I,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    if len(set(v)) <= 2:                 # e.g. "aaaaaa", "------"
        return True
    return bool(_PLACEHOLDER_RE.match(v))


@register
class SecretsScanner(Scanner):
    name = "secrets"
    category = "secrets"
    description = "Hardcoded credential detection across a local code path."

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def _scan_root(self, ctx: ScanContext) -> Path:
        raw = ctx.target.attributes.get("path") or ctx.target.raw
        p = Path(raw)
        return p if p.exists() and p.is_dir() else Path.cwd()

    def run(self, ctx: ScanContext) -> ScannerResult:
        res = ScannerResult(scanner=self.name)
        root = self._scan_root(ctx)
        repo_asset = Asset.make(AssetType.APP, str(root), attributes={"path": str(root)})
        ctx.asset_graph.add(repo_asset)

        scanned = 0
        skipped = 0
        # (label, value) -> Finding so the same secret is reported once with
        # every location attached as additional evidence.
        seen: Dict[Tuple[str, str], Finding] = {}

        for dirpath, dirnames, filenames in os.walk(root):
            # prune unwanted directories in place (do not descend into them)
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and d.lower() not in NOISE_PARTS]
            for fname in filenames:
                if not self._wanted_file(fname):
                    skipped += 1
                    continue
                path = Path(dirpath) / fname
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = path.read_text(errors="ignore")
                except Exception:
                    continue
                if "\x00" in text[:1024]:          # binary sniff
                    continue
                scanned += 1
                self._scan_text(ctx, repo_asset, path, text, seen, res)

        ctx.evidence_store.put(
            "scanner",
            f"Secrets scan inspected {scanned} files (skipped {skipped}) under {root}")
        res.notes.append(f"scanned {scanned} files, {len(res.findings)} unique secrets")
        return res

    def _wanted_file(self, fname: str) -> bool:
        low = fname.lower()
        if low in SCAN_FILENAMES or low.startswith(".env"):
            return True
        return Path(low).suffix in SCAN_EXTS

    def _scan_text(self, ctx: ScanContext, asset: Asset, path: Path, text: str,
                   seen: Dict[Tuple[str, str], Finding], res: ScannerResult) -> None:
        for label, pattern, severity, vgroup, needs_entropy in SIGNATURES:
            for m in pattern.finditer(text):
                value = m.group(vgroup) if vgroup <= (m.re.groups or 0) else None
                value = value or m.group(0)
                if needs_entropy:
                    if _is_placeholder(value):
                        continue
                    if _shannon_entropy(value) < ENTROPY_MIN:
                        continue
                line = text.count("\n", 0, m.start()) + 1
                ev = ctx.evidence_store.put(
                    "code", f"{label} matched in {path}:{line}",
                    raw={"file": str(path), "line": line, "match": value})
                key = (label, value)
                existing = seen.get(key)
                if existing is not None:
                    existing.add_evidence(Evidence(
                        "code", f"{label} also at {path}:{line} (value redacted).",
                        Confidence.HIGH, raw_ref=ev))
                    existing.notes.append(f"additional location: {path}:{line}")
                    continue
                finding = self._secret_finding(asset, label, path, line, severity, ev)
                seen[key] = finding
                res.findings.append(finding)

    def _secret_finding(self, asset: Asset, label: str, path: Path, line: int,
                        severity: Severity, ev_ref: str) -> Finding:
        return Finding(
            title=f"{label} hardcoded in source",
            asset=asset, scanner=self.name, category=Category.SECRETS.value,
            severity=severity, confidence=Confidence.HIGH,
            evidence=[Evidence("code",
                               f"{label} detected at {path}:{line} (value redacted).",
                               Confidence.HIGH, raw_ref=ev_ref)],
            impact=Impact(
                business="Leaked credential can grant unauthorized access.",
                technical=f"{label} committed to source at {path.name}:{line}.",
                blast_radius="any system the credential authenticates to"),
            remediation=Remediation(
                summary="Revoke and rotate the exposed credential; remove from history.",
                steps=["Revoke/rotate the credential immediately",
                       "Purge from git history (filter-repo/BFG)",
                       "Move secret to a managed secret store",
                       "Add pre-commit secret scanning"],
                priority=severity),
            owner=Owner(team="Application Security", service=str(path)),
            references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
        )
