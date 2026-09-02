"""Windows-safety lint for path segments (convention/datmeta.md rule V2).

The schema already blocks / \\ : * ? " < > |, leading dots and dot-only
segments; this covers what a regex reasonably cannot: reserved device names,
trailing dot or space, control characters.
"""

from __future__ import annotations

RESERVED = {"CON", "PRN", "AUX", "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}


def segment_issues(segment: str) -> list[str]:
    issues: list[str] = []
    stem = segment.split(".", 1)[0]  # Windows reserves CON and CON.txt alike
    if stem.upper() in RESERVED:
        issues.append("reserved device name")
    if segment and segment[-1] in ". ":
        issues.append("trailing dot or space")
    if any(ord(ch) < 32 for ch in segment):
        issues.append("control character")
    return issues


def path_issues(path: str) -> list[str]:
    """Lint a forward-slash relative path; returns 'segment: issue' strings."""
    out: list[str] = []
    for segment in path.split("/"):
        for issue in segment_issues(segment):
            out.append(f"'{segment}': {issue}")
    return out
