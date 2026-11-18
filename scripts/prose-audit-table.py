#!/usr/bin/env python3
"""Tabulate an adjudicated prose-audit file: outputs with >=1 A (memory) and >=1 E (deployment
assumption) per run x arm, lines per category, and the per-field split.

usage: scripts/prose-audit-table.py data/prose_audit/candidates-<date>.md

Denominators (usable outputs per run x arm) come from data/runs/<run>/results.csv. A category
written with a question mark or a slash ("A?", "A/D") is disputed: counted in its own column and
excluded from the firm counts, so the table shows whether the result depends on them. A note in
parentheses after the letter is kept; a note starting with "added" marks a line the adjudicator
added because the pre-screen missed it, and those are counted separately too.
"""
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

SECTION = re.compile(r"^## (\S+) (\S+) (CVE-\S+)\s*$")          # run arm cve
BLIND = re.compile(r"^## (\S+) (CVE-\S+) \[([0-9a-f]+)\]\s*$")     # run cve [token], arm in .arms-<date>.json
LINE = re.compile(r"^- `([^`]+)` \[(\w+)\] (.+?)\s+→ category:\s*(\S*)\s*(\(.*\))?\s*$")


def usable_outputs(run):
    counts = Counter()
    with open(f"data/runs/{run}/results.csv", newline="") as f:
        for row in csv.DictReader(f):
            if row["outcome"] in ("OK", "RECOVERED_AFTER_RETRY"):
                counts[row["arm"]] += 1
    return counts


def main(path):
    lines = defaultdict(list)  # (run, arm) -> [(cve, field, kind, phrase, category, added)]
    unfilled = []
    current = None
    arms = None
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        m = SECTION.match(raw)
        if m:
            current = (m[1], m[2], m[3])
            continue
        m = BLIND.match(raw)
        if m:
            if arms is None:
                stem = re.sub(r"^candidates-|\.md$", "", os.path.basename(path))
                arms_path = os.path.join(os.path.dirname(path), f".arms-{stem}.json")
                arms = json.load(open(arms_path))
            current = (m[1], arms[m[3]], m[2])
            continue
        m = LINE.match(raw)
        if m and current:
            cat = m[4].upper()
            if not cat:
                unfilled.append(n)
            note = m[5] or ""
            lines[current[:2]].append((current[2], m[1], m[2], m[3], cat, note.startswith("(added")))

    if unfilled:
        print(f"{len(unfilled)} unfilled line(s): {unfilled}", file=sys.stderr)

    firm = {"A", "B", "C", "D", "E"}
    keys = sorted(lines, key=lambda k: (k[0], k[1]))
    denom = {run: usable_outputs(run) for run in {k[0] for k in keys}}

    print("## Prose audit: adjudicated\n")
    print("| run | arm | outputs | ≥1 A | ≥1 E | ≥1 A or E | disputed lines | A | B | C | D | E | lines | added by adjudicator |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    per_field = defaultdict(Counter)
    for key in keys:
        run, arm = key
        rows = lines[key]
        cats = Counter(r[4] for r in rows)
        disputed = sum(v for k, v in cats.items() if k and k not in firm)
        with_a = len({r[0] for r in rows if r[4] == "A"})
        with_e = len({r[0] for r in rows if r[4] == "E"})
        with_ae = len({r[0] for r in rows if r[4] in ("A", "E")})
        n = denom[run][arm]
        print(f"| {run} | {arm} | {n} | {with_a} ({100*with_a/n:.0f}%) | {with_e} ({100*with_e/n:.0f}%) "
              f"| {with_ae} ({100*with_ae/n:.0f}%) | {disputed} | {cats['A']} | {cats['B']} | {cats['C']} "
              f"| {cats['D']} | {cats['E']} | {len(rows)} | {sum(1 for r in rows if r[5])} |")
        for r in rows:
            per_field[r[1]][r[4]] += 1

    print("\nDisputed lines:\n")
    for key in keys:
        for r in lines[key]:
            if r[4] and r[4] not in firm:
                print(f"- {key[0]} {key[1]} {r[0]} `{r[1]}` {r[3]} → {r[4]}")

    print("\n### Per field (all runs and arms)\n")
    print("| field | A | E | B | C | D | total |")
    print("|---|---|---|---|---|---|---|")
    for field, c in sorted(per_field.items(), key=lambda kv: -(kv[1]["A"] + kv[1]["E"])):
        print(f"| `{field}` | {c['A']} | {c['E']} | {c['B']} | {c['C']} | {c['D']} | {sum(c.values())} |")

    print("\n### A and E phrases per CVE\n")
    by_cve = defaultdict(lambda: defaultdict(list))
    for key, rows in lines.items():
        for r in rows:
            if r[4] in ("A", "E"):
                by_cve[r[0]][key].append(f"{r[4]}:{r[3]}")
    for cve in sorted(by_cve):
        cells = "; ".join(f"{k[0][4:8]}/{k[1]} " + ", ".join(v) for k, v in sorted(by_cve[cve].items()))
        print(f"- {cve}: {cells}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/prose_audit/candidates-20261113.md")
