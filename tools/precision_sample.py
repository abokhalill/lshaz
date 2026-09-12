#!/usr/bin/env python3
"""Draw a blind, reproducible sample of findings for precision adjudication.

A desk enables rules individually, so a pooled precision number tells an
operator nothing about the rule they turned on: it is dominated by whichever
rule is most prolific. Everything here is per (rule, severity).

Two properties the sample must have, or the resulting number is not evidence:

  reproducible  the sample is drawn with a fixed seed from a canonical
                ordering, so it cannot be redrawn until it looks good, and
                anyone can regenerate the identical worksheet.

  blind         the worksheet omits lshaz's severity, confidence and
                evidence tier. An adjudicator who sees the tool's own grade
                anchors to it, and the measurement then partly measures the
                tool's persuasiveness rather than its correctness.

  sample   scan.json worksheet.json [--per-stratum N] [--seed S]
  score    worksheet.json           (after verdicts are filled in)
"""
import argparse
import collections
import hashlib
import json
import math
import random
import sys

# Verdicts an adjudicator may record. TP-NWF is kept distinct because it is
# a hotness failure, not a mechanism failure, and the two call for different
# fixes -- pooling them hides which one is actually broken.
VERDICTS = {
    "TP":     "mechanism applies and the site is worth acting on",
    "TP-NWF": "mechanism applies but the site is cold; not worth fixing",
    "FP":     "the stated mechanism cannot apply at this site",
    "?":      "not adjudicated",
}


def canonical_key(d):
    loc = d.get("location", {})
    return (d.get("ruleID", ""), loc.get("file", ""), loc.get("line", 0),
            loc.get("column", 0), d.get("functionName", ""))


def source_context(path, line, radius=6):
    try:
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
    except OSError as e:
        return [f"<source unavailable: {e}>"]
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    return [f"{i+1:6d}{'>' if i + 1 == line else ' '} {lines[i].rstrip()}"
            for i in range(lo, hi)]


def cmd_sample(args):
    with open(args.scan) as fh:
        diags = json.load(fh)["diagnostics"]
    diags = [d for d in diags if not d.get("suppressed")]

    strata = collections.defaultdict(list)
    for d in diags:
        strata[(d.get("ruleID", "?"), d.get("severity", "?"))].append(d)

    worksheet = {
        "source_scan": args.scan,
        "seed": args.seed,
        "per_stratum": args.per_stratum,
        "population": {f"{r}/{s}": len(v) for (r, s), v in sorted(strata.items())},
        "verdict_legend": VERDICTS,
        "adjudicators": [],
        "items": [],
    }

    for (rule, sev), pool in sorted(strata.items()):
        pool.sort(key=canonical_key)
        # Seed per stratum so adding a rule does not reshuffle other strata.
        rng = random.Random(f"{args.seed}:{rule}:{sev}")
        picked = pool if len(pool) <= args.per_stratum else rng.sample(
            pool, args.per_stratum)
        picked.sort(key=canonical_key)
        for d in picked:
            loc = d.get("location", {})
            worksheet["items"].append({
                "id": hashlib.sha1(
                    repr(canonical_key(d)).encode()).hexdigest()[:12],
                "rule": rule,
                # stratum severity is retained for scoring but the reviewer
                # is told not to read it; keeping it out entirely would make
                # per-severity precision unrecoverable.
                "_stratum_severity": sev,
                "site": f"{loc.get('file','?')}:{loc.get('line',0)}",
                "function": d.get("functionName", ""),
                "mechanism": d.get("hardwareReasoning", ""),
                "claims": [
                    {"effect": c.get("effect"),
                     "precondition": c.get("precondition"),
                     "established": c.get("established"),
                     "gating": c.get("gating", False)}
                    for c in d.get("mechanismClaims", [])
                ],
                "evidence": d.get("structuralEvidence", {}),
                "context": source_context(loc.get("file", ""),
                                          loc.get("line", 0)),
                "verdict": "?",
                "rationale": "",
            })

    with open(args.worksheet, "w") as fh:
        json.dump(worksheet, fh, indent=2)
    print(f"{len(worksheet['items'])} item(s) across "
          f"{len(strata)} stratum/strata -> {args.worksheet}")
    return 0


def wilson(k, n, z=1.96):
    """Wilson score interval. Normal approximation collapses at the extremes,
    and precision samples land at the extremes routinely."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def cmd_score(args):
    with open(args.worksheet) as fh:
        ws = json.load(fh)
    items = ws["items"]
    unjudged = [i for i in items if i["verdict"] == "?"]

    by_rule = collections.defaultdict(collections.Counter)
    for i in items:
        by_rule[i["rule"]][i["verdict"]] += 1

    print(f"scan       : {ws['source_scan']}")
    print(f"adjudicator: {', '.join(ws.get('adjudicators')) or 'UNRECORDED'}")
    if len(ws.get("adjudicators", [])) < 2:
        print("             single adjudicator -- not a desk-grade number")
    print(f"unjudged   : {len(unjudged)} of {len(items)}\n")

    print(f"{'rule':8} {'n':>4} {'TP':>4} {'NWF':>4} {'FP':>4} "
          f"{'precision':>10}  95% CI")
    overall = collections.Counter()
    for rule in sorted(by_rule):
        c = by_rule[rule]
        overall.update(c)
        n = c["TP"] + c["TP-NWF"] + c["FP"]
        if n == 0:
            print(f"{rule:8} {'-':>4}  (unjudged)")
            continue
        # TP-NWF counts as correct: the mechanism holds. Whether the site is
        # worth fixing is a hotness question, reported separately.
        k = c["TP"] + c["TP-NWF"]
        lo, hi = wilson(k, n)
        print(f"{rule:8} {n:4d} {c['TP']:4d} {c['TP-NWF']:4d} {c['FP']:4d} "
              f"{k/n:10.2f}  [{lo:.2f}, {hi:.2f}]")

    n = overall["TP"] + overall["TP-NWF"] + overall["FP"]
    if n:
        k = overall["TP"] + overall["TP-NWF"]
        lo, hi = wilson(k, n)
        print(f"\npooled   {n:4d} {overall['TP']:4d} {overall['TP-NWF']:4d} "
              f"{overall['FP']:4d} {k/n:10.2f}  [{lo:.2f}, {hi:.2f}]")
        print("pooled is reported for completeness only; it is dominated by "
              "the most prolific rule and no operator enables 'all rules'.")
    return 1 if unjudged else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample")
    s.add_argument("scan")
    s.add_argument("worksheet")
    s.add_argument("--per-stratum", type=int, default=8)
    s.add_argument("--seed", default="lshaz")
    s.set_defaults(fn=cmd_sample)

    c = sub.add_parser("score")
    c.add_argument("worksheet")
    c.set_defaults(fn=cmd_score)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
