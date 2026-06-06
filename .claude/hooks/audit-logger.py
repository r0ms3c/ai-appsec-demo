#!/usr/bin/env python3
"""
audit-logger hook
Event: PostToolUse — fires after every Bash tool call
Purpose: Maintain an audit trail of every shell command Claude executes
Log location: .claude/audit.log (JSONL — one entry per line)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


RISK_RULES = [
    ("high",   "credential or secret access",   r"(?i)(cat|head|tail).*(secret|\.env|\.pem|id_rsa|\.key)"),
    ("high",   "privilege escalation",          r"\bsudo\b|\bsu\b"),
    ("high",   "network exfiltration risk",     r"\b(curl|wget|nc|netcat)\b.*(http|ftp)"),
    ("high",   "reading sensitive system file", r"(?i)(cat|head|tail).*/etc/(passwd|shadow|sudoers)"),
    ("high",   "installing software",           r"\b(pip install|npm install|apt install)\b"),
    ("medium", "git operation",                 r"\bgit\b"),
    ("medium", "file deletion",                 r"\brm\b"),
    ("low",    "read operation",                r"\b(cat|ls|find|grep|head|tail)\b"),
    ("low",    "build operation",               r"\b(make|cargo build|go build)\b"),
]


def classify(command: str) -> tuple:
    for level, reason, pattern in RISK_RULES:
        if re.search(pattern, command):
            return level, reason
    return "low", "standard command"


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    if data.get("tool_name") != "Bash":
        sys.exit(0)

    command   = data.get("tool_input", {}).get("command", "")
    exit_code = data.get("tool_response", {}).get("exit_code")
    risk, reason = classify(command)

    entry = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "session_id": os.environ.get("CLAUDE_SESSION_ID", "unknown"),
        "command":    command,
        "exit_code":  exit_code,
        "risk_level": risk,
        "risk_reason": reason,
    }

    log_path = Path(".claude/audit.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    if risk == "high":
        print(f"⚠️  AUDIT: High-risk command logged — {reason}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
