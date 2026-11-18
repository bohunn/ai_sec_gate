#!/usr/bin/env python3
"""Pre-screen the prose fields of a recorded run for phrases absent from the input the model saw.

usage: scripts/prose-prescreen.py <run-stamp> [--write data/prose_audit/candidates-<date>.md]

The oracle is the serialized CveInput (`app input <CVE>`), the same bytes the model received; never
the raw NVD record. Without --write the per-arm summary is printed and nothing is written.

With --write the candidates file is written for blind adjudication: each section names the run and
the CVE but replaces the arm with a random token, and the token -> arm map goes to a sibling file
`.arms-<date>.json`. The adjudicator does not open that file until every line has a letter;
`scripts/prose-audit-table.py` reads the map to restore the arm.

A section whose output declared memory in `background_knowledge` says so under its header, so the
adjudicator can tell a leak next to an empty outlet from a leak that duplicates a declared item.

Kinds are hints, not categories: `world` needs world knowledge (A or D after adjudication),
`context` is a deployment assumption (E or C), `date` and `name` are specific tokens absent from
the input (any category).
"""
import collections
import glob
import json
import os
import re
import secrets
import subprocess
import sys

APP = "app/build/install/app/bin/app"
PROSE = [("summary",), ("severity", "adjustment_reason"), ("impact", "worst_case"),
         ("remediation", "detail"), ("remediation", "workaround"), ("rationale",)]
WORLD = ["end-of-life", "end of life", "eol", "legacy", "discontinued", "no longer supported",
         "unsupported", "metasploit", "nuclei", "kev", "cisa", "known to be", "historically",
         "in the wild", "actively exploited", "ransomware", "botnet", "mirai", "consumer router",
         "embedded"]
CONTEXT = ["internet-exposed", "internet-facing", "internet exposed", "internet facing",
           "publicly exposed", "commonly", "widely", "typically", "usually", "ubiquitous", "popular",
           "default credentials", "most deployments", "typical deployment", "in practice", "rarely",
           "often", "unlikely to be exposed"]
MONTHS = "january|february|march|april|may|june|july|august|september|october|november|december"
STOP = set("The This It If When No An A For With Without Because However Although While Since Any "
           "All Only Both Use Upgrade Apply Patch Replace Remove Restrict Block Treat Monitor Review "
           "Confirm Check Verify Disable Enable Limit Rebuild Redeploy Pin Set Add Ensure Avoid Do "
           "Not Never Prefer Keep Run Consider There These Those Its Their".split())
ACRONYMS = {"NVD", "CVSS", "CWE", "CPE", "KEV"}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def get(t, path):
    for p in path:
        t = t.get(p) if isinstance(t, dict) else None
    return t or ""


_inputs = {}


def model_input(cve):
    if cve not in _inputs:
        out = subprocess.run([APP, "input", cve], capture_output=True, text=True, check=True).stdout
        _inputs[cve] = norm(out)
    return _inputs[cve]


def candidates(triage, inp):
    hits = set()
    for path in PROSE:
        text = get(triage, path)
        low = text.lower()
        field = ".".join(path)
        for m in WORLD:
            if re.search(r"\b" + re.escape(m) + r"\b", low) and norm(m) not in inp:
                hits.add((field, "world", m))
        for m in CONTEXT:
            if re.search(r"\b" + re.escape(m) + r"\b", low) and norm(m) not in inp:
                hits.add((field, "context", m))
        for mo in re.findall(r"\b(?:%s)\s+\d{4}\b" % MONTHS, low):
            if norm(mo) not in inp:
                hits.add((field, "date", mo))
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            for w in sentence.split()[1:]:
                c = w.strip(".,;:()[]\"'")
                if (len(c) > 2 and c[0].isupper() and not c.isupper() and c not in STOP
                        and c not in ACRONYMS and norm(c) and norm(c) not in inp):
                    hits.add((field, "name", c))
    return sorted(hits)


def main():
    args = sys.argv[1:]
    write = None
    if "--write" in args:
        i = args.index("--write")
        write = args[i + 1]
        del args[i:i + 2]
    run = args[0]
    sections = []
    declared = {}
    total = collections.Counter()
    flagged = collections.Counter()
    kinds = collections.Counter()
    for p in sorted(glob.glob(f"data/runs/{run}/raw/run1/*.json")):
        r = json.load(open(p))
        t = r.get("triage")
        if not t or r["outcome"] not in ("OK", "RECOVERED_AFTER_RETRY"):
            continue
        arm, cve = os.path.basename(p)[:-5].split("-", 1)
        total[arm] += 1
        declared[(arm, cve)] = len(t.get("background_knowledge") or [])
        hits = candidates(t, model_input(cve))
        if hits:
            flagged[arm] += 1
            for _, k, _ in hits:
                kinds[k] += 1
            sections.append((arm, cve, hits))

    print(f"run {run}: " + ", ".join(
        f"{arm} {flagged[arm]}/{total[arm]} outputs flagged" for arm in sorted(total)))
    print("outputs declaring background_knowledge: " + ", ".join(
        f"{arm} {sum(1 for (a, c), n in declared.items() if a == arm and n)}/{total[arm]}"
        for arm in sorted(total)))
    print("lines by kind: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
    if not write:
        return

    stem = re.sub(r"^candidates-|\.md$", "", os.path.basename(write))
    arms_path = os.path.join(os.path.dirname(write), f".arms-{stem}.json")
    tokens = {}
    secrets.SystemRandom().shuffle(sections)  # file order must not follow the arm
    out = [f"# Prose-audit candidates (automatic pre-screen of run {run}, blind to arm)", "",
           "Provenance, not truth: each line is a phrase found in a prose field but **not in the input the",
           "model saw** (`app input <CVE>`). The pre-screen is deliberately wide. Assign each line one letter",
           "after `→ category:` (A memory, B paraphrase, C generic, D inference, E deployment assumption;",
           "VALIDATION.md, \"Prose audit\"). Add a line in the same format for an A or E claim the pre-screen",
           "missed, with a note `(added: ...)`. Mark doubt as `A?` or `A/D`.", "",
           f"The arm is hidden behind a per-section token; the map is in `{os.path.basename(arms_path)}`.",
           "Do not open it before the last letter is in. The output file for a section is",
           "`data/runs/<run>/raw/run1/<arm>-<CVE>.json`; `scripts/prose-worksheet.py` renders input and",
           "output side by side without revealing the arm.", ""]
    for arm, cve, hits in sections:
        tok = secrets.token_hex(3)
        while tok in tokens:
            tok = secrets.token_hex(3)
        tokens[tok] = arm
        out.append(f"## {run} {cve} [{tok}]")
        if declared.get((arm, cve)):
            out.append(f"declared background_knowledge: {declared[(arm, cve)]} item(s)")
        for field, kind, val in hits:
            out.append(f"- `{field}` [{kind}] {val}  → category: ")
        out.append("")
    open(write, "w", encoding="utf-8").write("\n".join(out))
    json.dump(tokens, open(arms_path, "w"), indent=1, sort_keys=True)
    print(f"wrote {write} ({len(sections)} sections, {sum(kinds.values())} lines) and {arms_path}")


if __name__ == "__main__":
    main()
