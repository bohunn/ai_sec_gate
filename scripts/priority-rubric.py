#!/usr/bin/env python3
"""Score a priority rubric against every recorded, trustworthy output (decision 8).

usage: scripts/priority-rubric.py [--variant candidate|revised] [--no-description-evidence]

Both variants are pure functions of (adjusted_severity, verdict, exploit evidence in the input). The
exploit evidence is read from the serialized CveInput: a KEV listing, an Exploit reference tag, or
exploit words in the description. The output is the agreement with the model's own `priority`, the
confusion between rubric and model, and the per-CVE split, so the rubric is judged on data before
it is adopted. The candidate was written after seeing CVE-2026-86509 (VALIDATION.md, decision 8).
"""
import collections
import glob
import json
import re
import subprocess
import sys

APP = "app/build/install/app/bin/app"
EXPLOIT_WORDS = re.compile(r"\b(exploit(ed|ation|s)?|proof[- ]of[- ]concept|poc|metasploit|in the wild)\b", re.I)
RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": -1}
_inputs = {}


def model_input(cve):
    if cve not in _inputs:
        out = subprocess.run([APP, "input", cve], capture_output=True, text=True, check=True).stdout
        _inputs[cve] = json.loads(out)
    return _inputs[cve]


def evidence(i, description_counts):
    kinds = set()
    if i.get("known_exploited"):
        kinds.add("kev")
    if any("Exploit" in (r.get("tags") or []) for r in i.get("references", [])):
        kinds.add("tag")
    if description_counts and EXPLOIT_WORDS.search(i.get("description", "")):
        kinds.add("desc")
    return kinds


def candidate(adj, verdict, ev):
    """VALIDATION.md decision 8, as written: P0 when BLOCK or KEV-listed; P1 when adjusted >= HIGH
    with exploit evidence; P2 when adjusted HIGH without evidence, or MEDIUM; P3 otherwise."""
    if verdict == "BLOCK" or "kev" in ev:
        return "P0"
    if RANK[adj] >= 3 and ev:
        return "P1"
    if adj in ("HIGH", "MEDIUM"):
        return "P2"
    return "P3"


def revised(adj, verdict, ev):
    """The candidate with its gap closed: adjusted CRITICAL is never below P1, and a BLOCK is P0
    only when CRITICAL. P0: KEV, or BLOCK + CRITICAL. P1: CRITICAL, or HIGH with evidence or BLOCK.
    P2: HIGH without evidence, or MEDIUM. P3: LOW, NONE, UNKNOWN."""
    if "kev" in ev or (verdict == "BLOCK" and adj == "CRITICAL"):
        return "P0"
    if adj == "CRITICAL" or (adj == "HIGH" and (ev or verdict == "BLOCK")):
        return "P1"
    if adj in ("HIGH", "MEDIUM"):
        return "P2"
    return "P3"


def main():
    variant = revised if "--variant" in sys.argv and sys.argv[sys.argv.index("--variant") + 1] == "revised" else candidate
    use_desc = "--no-description-evidence" not in sys.argv
    n = agree = 0
    confusion = collections.Counter()
    per_cve = collections.defaultdict(collections.Counter)
    for path in sorted(glob.glob("data/runs/*/raw/run1/*.json")):
        r = json.load(open(path))
        t = r.get("triage")
        if not t or r["outcome"] not in ("OK", "RECOVERED_AFTER_RETRY"):
            continue
        cve = t["cve_id"]
        ev = evidence(model_input(cve), use_desc)
        rubric = variant(t["severity"]["adjusted_severity"], t["verdict"], ev)
        n += 1
        agree += rubric == t["priority"]
        confusion[(rubric, t["priority"])] += 1
        per_cve[cve][(t["priority"], rubric)] += 1
    print(f"rubric: {variant.__name__}, description evidence {'counted' if use_desc else 'ignored'}")
    print(f"agreement with the model's priority: {agree}/{n} ({100 * agree / n:.0f}%)")
    print("disagreements (rubric -> model: outputs): "
          + ", ".join(f"{a}->{b}: {v}" for (a, b), v in sorted(confusion.items()) if a != b))
    print("\nper CVE (model priority, rubric priority): outputs, only where they ever differ")
    for cve, c in sorted(per_cve.items()):
        if any(a != b for a, b in c):
            print(f"  {cve}: " + ", ".join(f"model {a} rubric {b}: {v}" for (a, b), v in sorted(c.items())))


if __name__ == "__main__":
    main()
