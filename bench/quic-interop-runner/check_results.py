# ABOUTME: Compares a quic-interop-runner results.json (enso as server) with expected-results.txt and
# ABOUTME: prints a client x test table (also to $GITHUB_STEP_SUMMARY); exit 1 = no results, 2 = mismatch.
"""Usage: check_results.py RESULTS_JSON EXPECTED_RESULTS

EXPECTED_RESULTS lines are `<client> <test> <result>`, result one of
succeeded / failed / unsupported; `#` starts a comment. Every pair that
ran must be listed with the result it produced: a pair that ran but is
not listed, or produced another result, is a mismatch (a fixed failure
too, so the file stays current); so is a pair that was selected but never
ran. Listed pairs that did not run (clients
or tests not selected) are ignored.
"""
import json
import os
import sys


def load_expected(path):
    expected = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3 or parts[2] not in ("succeeded", "failed", "unsupported"):
                sys.exit(f"{path}:{n}: expected '<client> <test> succeeded|failed|unsupported'")
            expected[(parts[0], parts[1])] = parts[2]
    return expected


def load_results(path):
    """{(client, test): result} for the enso server."""
    with open(path) as f:
        data = json.load(f)
    servers, clients = data["servers"], data["clients"]
    results = {}
    # results[] is ordered client-major, then server (interop.py _export_results).
    for ci, client in enumerate(clients):
        for si, server in enumerate(servers):
            if server != "enso":
                continue
            for r in data["results"][ci * len(servers) + si]:
                results[(client, r["name"])] = r["result"]
    return results


def main(results_path, expected_path):
    if not os.path.exists(results_path):
        print(f"no results at {results_path}: the runner failed before writing them", file=sys.stderr)
        return 1
    results = load_results(results_path)
    if not results:
        print("the runner recorded no results", file=sys.stderr)
        return 1
    expected = load_expected(expected_path)
    rows = []
    mismatches = 0
    for (client, test), result in sorted(results.items()):
        want = expected.get((client, test))
        # None: the pair never ran (an endpoint failed the runner's
        # compliance check, or the run broke off); never a match.
        if result is None:
            result = "not run"
        ok = result == want
        if not ok:
            mismatches += 1
        rows.append(f"| {client} | {test} | {result} | {want or 'not listed'} | {'ok' if ok else '**mismatch**'} |")
    table = "\n".join(
        ["### QUIC interop (enso server)", "",
         "| client | test | result | expected | |", "|---|---|---|---|---|"] + rows + [""])
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(table + "\n")
    if mismatches:
        print(f"{mismatches} result(s) differ from {expected_path}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
