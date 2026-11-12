#!/usr/bin/env python3
"""Turn study/results/*.json into a redacted Markdown matrix (statuses only)."""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MARK = {"exposed": "EXPOSED", "protected": "ok", "na": "-"}


def main():
    files = sorted(glob.glob(os.path.join(HERE, "results", "*.json")))
    runs = []
    for path in files:
        try:
            with open(path) as fh:
                runs.append((os.path.basename(path)[:-5], json.load(fh)))
        except ValueError:
            print("skipping unreadable result: %s" % path, file=sys.stderr)
    if not runs:
        sys.exit("no results; run study/run_local.sh first")

    probes = []  # (id, category, title) in first-seen order
    for _, data in runs:
        for r in data["results"]:
            if r["id"] not in [p[0] for p in probes]:
                probes.append((r["id"], r["category"], r["title"]))

    names = [n for n, _ in runs]
    print("| Probe | " + " | ".join(names) + " |")
    print("|---|" + "---|" * len(names))
    print("| **Score / grade** | " + " | ".join("**%d / %s**" % (d["score"], d["grade"]) for _, d in runs) + " |")
    for sev in ("critical", "high", "medium", "low"):
        counts = [sum(1 for r in d["results"] if r["status"] == "exposed" and r["severity"] == sev) for _, d in runs]
        print("| exposed, %s | " % sev + " | ".join(str(c) for c in counts) + " |")
    category = None
    for pid, cat, title in probes:
        if cat != category:
            category = cat
            print("| **%s** |" % cat + " |" * len(names))
        cells = []
        for _, data in runs:
            hit = next((r for r in data["results"] if r["id"] == pid), None)
            cells.append("n/t" if hit is None else
                         ("EXPOSED (%s)" % hit["severity"] if hit["status"] == "exposed" else MARK[hit["status"]]))
        print("| %s | " % title + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
