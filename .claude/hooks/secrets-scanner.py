#!/usr/bin/env python3
"""
secrets-scanner hook
Event: PreToolUse — fires before Write, Edit, MultiEdit
Purpose: Block file writes containing secret patterns before they hit disk
Exit 0 = allow | Exit 2 = block and feed findings back to Claude
"""

import json
import re
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class Pattern:
    name: str
    regex: str
    confidence: str


PATTERNS = [
    Pattern("AWS Access Key ID",    r"AKIA[0-9A-Z]{16}",                                              "high"),
    Pattern("Generic API Key",      r"(?i)(api[_-]?key)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]",    "high"),
    Pattern("Generic Secret",       r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]", "high"),
    Pattern("Generic Token",        r"(?i)(token|auth[_-]?token)\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{20,}['\"]", "high"),
    Pattern("Generic Password",     r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",       "medium"),
    Pattern("GitHub Token",         r"ghp_[0-9a-zA-Z]{36}",                                           "high"),
    Pattern("Slack Token",          r"xox[baprs]-[0-9a-zA-Z\-]+",                                     "high"),
    Pattern("Private Key (PEM)",    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                "high"),
    Pattern("Database URL",         r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]{3,}@",           "high"),
]

ALLOWLIST = [
    r"(?i)(example|sample|fake|dummy|test|placeholder)",
    r"<[A-Z_]+>",
    r"\$\{[^}]+\}",
    r"\{\{[^}]+\}\}",
]


def redact(match: str) -> str:
    return match[:4] + "***" + match[-4:] if len(match) > 8 else "***"


def is_allowlisted(line: str) -> bool:
    return any(re.search(p, line) for p in ALLOWLIST)


def scan(content: str) -> list:
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        if is_allowlisted(line):
            continue
        for p in PATTERNS:
            m = re.search(p.regex, line)
            if m:
                findings.append((p.name, p.confidence, i, redact(m.group(0))))
    return findings


def extract_content(tool_input: dict) -> Optional[str]:
    if "content" in tool_input:
        return tool_input["content"]
    if "new_str" in tool_input:
        return tool_input["new_str"]
    if "edits" in tool_input:
        return "\n".join(e.get("new_str", "") for e in tool_input.get("edits", []))
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    content = extract_content(data.get("tool_input", {}))
    if not content:
        sys.exit(0)

    findings = scan(content)
    if not findings:
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("path", "unknown")
    lines = [
        f"🔑 SECRETS SCANNER: {len(findings)} potential secret(s) detected in {file_path}",
        "",
        "Write blocked. Remove secrets before proceeding.",
        "",
    ]
    for name, confidence, lineno, snippet in findings:
        lines.append(f"  [{confidence.upper()}] Line {lineno}: {name} — {snippet}")
    lines += [
        "",
        "Fix: move secrets to environment variables or a secrets manager.",
        "For test fixtures with fake values, add: # fake/example",
    ]
    print("\n".join(lines))
    sys.exit(2)


if __name__ == "__main__":
    main()
