"""Minimal scaffold checks for human-approved planned signatures.

This module does not parse source and does not provide structural evidence.
The configured compiler validates generated scaffolds; direct SCIP binds the
resulting subjects.
"""

from __future__ import annotations

import re

_FUNCTION = re.compile(r"^(?P<prefix>async\s+def|def)\s+(?P<name>[A-Za-z_]\w*)\s*\(")


def normalize_python_function_signature(signature: str) -> tuple[str, str]:
    """Return a renderable planned function header and its lexical name."""
    candidate = signature.strip()
    header = candidate[:-1].rstrip() if candidate.endswith(":") else candidate
    match = _FUNCTION.match(header)
    if match is None:
        raise ValueError("Python function signature must start with def NAME( or async def NAME(")
    if "\n" in header or "\r" in header:
        raise ValueError("Python function signature must occupy one line")
    return header, match.group("name")
