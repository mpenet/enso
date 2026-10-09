# ABOUTME: Splits an h2spec JUnit report into failing and passing case ids, one per line in two files.
# ABOUTME: Ids are "<section>/<n>: <description>", n being h2spec's 1-based case number.
import sys
import xml.etree.ElementTree as ET

report, failures_path, passes_path = sys.argv[1:4]
root = ET.parse(report).getroot()
with open(failures_path, "w") as failures, open(passes_path, "w") as passes:
    for suite in root.iter("testsuite"):
        for n, case in enumerate(suite.iter("testcase"), start=1):
            failed = case.find("failure") is not None or case.find("error") is not None
            out = failures if failed else passes
            out.write(f"{case.get('package')}/{n}: {case.get('classname')}\n")
