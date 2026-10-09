# ABOUTME: Splits an Autobahn fuzzingclient index.json into failing and passing case ids, one per
# ABOUTME: line in two files; failures as "<case> <behavior>/<behaviorClose>", passes as "<case>".
import json
import sys

# Outcomes Autobahn itself counts as passing.
PASSING = {"OK", "NON-STRICT", "INFORMATIONAL"}
PASSING_CLOSE = {"OK", "INFORMATIONAL"}


def case_key(case_id):
    return [int(p) for p in case_id.split(".")]


index_path, failures_path, passes_path = sys.argv[1:4]
with open(index_path) as f:
    index = json.load(f)

with open(failures_path, "w") as failures, open(passes_path, "w") as passes:
    for agent, cases in index.items():
        for case_id in sorted(cases, key=case_key):
            r = cases[case_id]
            if r["behavior"] not in PASSING or r["behaviorClose"] not in PASSING_CLOSE:
                failures.write(f"{case_id} {r['behavior']}/{r['behaviorClose']}\n")
            else:
                passes.write(f"{case_id}\n")
