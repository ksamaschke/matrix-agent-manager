#!/usr/bin/env python3
"""Reject deployment-specific values and private material from the product tree."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXCLUDED_PARTS = {".git", ".github"}
HOSTNAME_MARKERS = (
    "samaschke.de",
    "vanillacore",
    "auth.vanillacore.net",
    "matrix.home",
    "admin.matrix",
)
PRIVATE_KEY = re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY")
LITERAL_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")

violations: list[str] = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.relative_to(ROOT).parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    rel = path.relative_to(ROOT)
    for line_number, line in enumerate(text.splitlines(), 1):
        if any(marker in line for marker in HOSTNAME_MARKERS):
            violations.append(f"{rel}:{line_number}: deployment-specific hostname")
        if PRIVATE_KEY.search(line):
            violations.append(f"{rel}:{line_number}: private-key marker")
        if LITERAL_BEARER.search(line) and "synthetic" not in line.lower():
            violations.append(f"{rel}:{line_number}: non-synthetic bearer token literal")

if violations:
    print("source hygiene violations:")
    print("\n".join(violations))
    sys.exit(1)
print("source hygiene scan passed")
