#!/usr/bin/env python3
"""Render a reading aid for prose-audit adjudication: for each section of a candidates file, the
input the model saw, its six prose fields with the candidate phrases marked in bold, and the
candidate lines. Letters are filled in the candidates file, not here.

usage: scripts/prose-worksheet.py data/prose_audit/candidates-<date>.md > data/prose_audit/worksheet-<date>.md

Handles both header forms (`## run arm CVE` and the blind `## run CVE [token]`); for the blind form
the arm is read from `.arms-<date>.json` only to locate the output file and is never printed.
Worksheets carry raw model outputs and are gitignored.
"""
import json
import os
import re
import subprocess
import sys

APP = "app/build/install/app/bin/app"
SECTION = re.compile(r"^## (\S+) (\S+) (CVE-\S+)\s*$")
BLIND = re.compile(r"^## (\S+) (CVE-\S+) \[([0-9a-f]+)\]\s*$")
LINE = re.compile(r"^- `([^`]+)` \[(\w+)\] (.+?)\s+→ category:(.*)$")
PROSE = [("summary",), ("severity", "adjustment_reason"), ("impact", "worst_case"),
         ("remediation", "detail"), ("remediation", "workaround"), ("rationale",)]
LEGEND = """## Category legend

The question is provenance, not truth: **was this in the input?** A true fact from memory is still A.

| | Category | Test | Example |
|---|---|---|---|
| **A** | **memory** | a fact about the world the record does not contain; needs a calendar, a product catalogue, brand knowledge or "what is typical" | "DIR-895L is end-of-life"; "MSIE" written as "Internet Explorer"; "unsupported product" when the record says nothing about vendor support |
| B | paraphrase | restates something that is in the input, in other words | record: "AutoProtect feature would detect the virus before it is executed" → output: "AutoProtect on-access scanner" |
| C | generic | triage language that asserts nothing about this CVE | "upgrade when a fix is available"; "monitor vendor advisories" |
| D | inference | follows from the input alone. Deciding test: *would a reader with only the input and no knowledge of the world reach it?* | published 2002 → "old", "2002-era product"; `version: 2.0` → "legacy CVSS rating" |
| **E** | **deployment assumption** | a claim about how the component is deployed or used, which neither the record nor training data can supply | "internet-exposed"; "commonly deployed at the edge"; "unlikely to be present in a modern build" |

Only **A** and **E** count toward the metric, reported separately. D is allowed and wanted.
Doubt between A and D: if the sentence needs anything beyond the date, the version numbers and the
description text, it is A. Unsure: write `A?` or `A/D`; disputed lines are counted separately.
If a sentence contains an A or E claim the pre-screen missed, add a line in the same format with a
note `(added: ...)`. The `[kind]` tag is the pre-screen's hint, not the answer.
"""


def get(t, path):
    for p in path:
        t = t.get(p) if isinstance(t, dict) else None
    return t


def main(path):
    stem = re.sub(r"^candidates-|\.md$", "", os.path.basename(path))
    arms_path = os.path.join(os.path.dirname(path), f".arms-{stem}.json")
    arms = json.load(open(arms_path)) if os.path.exists(arms_path) else {}
    sections = []
    for raw in open(path, encoding="utf-8"):
        m = SECTION.match(raw)
        if m:
            sections.append({"run": m[1], "arm": m[2], "cve": m[3], "header": raw.rstrip(), "cands": []})
            continue
        m = BLIND.match(raw)
        if m:
            sections.append({"run": m[1], "arm": arms[m[3]], "cve": m[2], "header": raw.rstrip(), "cands": []})
            continue
        m = LINE.match(raw)
        if m and sections:
            sections[-1]["cands"].append(raw.rstrip())
            sections[-1].setdefault("phrases", []).append(m[3])

    out = [f"# Prose-audit worksheet (generated from {os.path.basename(path)})", "",
           "Per output: the input the model saw, then its six prose fields with candidate phrases marked",
           "**like this**, then the candidate lines. Fill the letter after `→ category:` in the candidates",
           "file; this file is a reading aid.", "", LEGEND]
    inputs = {}
    for s in sections:
        cve = s["cve"]
        if cve not in inputs:
            inputs[cve] = subprocess.run([APP, "input", cve], capture_output=True, text=True, check=True).stdout.strip()
        raw = json.load(open(f"data/runs/{s['run']}/raw/run1/{s['arm']}-{cve}.json"))
        t = raw.get("triage", raw)
        out += [s["header"], "", "**Input:**", "", "```json", inputs[cve], "```", "", "**Output prose:**", ""]
        for p in PROSE:
            v = get(t, p)
            if not v:
                continue
            for ph in sorted(set(s.get("phrases", [])), key=len, reverse=True):
                v = re.sub(re.escape(ph), lambda m: f"**{m[0]}**", v)
            out.append(f"- `{'.'.join(p)}`: {v}")
        declared = t.get("background_knowledge") or []
        out += ["", f"**Declared background_knowledge ({len(declared)}):**", ""]
        out += [f"- {item}" for item in declared] or ["- (none)"]
        out += ["", "**Candidates:**", ""] + s["cands"] + [""]
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1])
