#!/usr/bin/env python3
"""The tests a CI job skipped, and whether it expected each.

A test that cannot run on a machine (it needs root, Landlock, a user's
systemd, python3) returns early and prints a line that starts with
`skipped`, with why. Run with `-- --show-output`, cargo test prints that
line under the test's name, in a block `---- <name> stdout ----`. This script
reads such a log, lists every test that skipped and why, and fails when one
of them is not in the job's list in .github/test-skips.txt: a runner that
loses Landlock or a user session then turns the job red instead of passing
with less tested. A name in the list that did not skip is only noted, as
the list says what may skip, not what must.

    skips.py --job <job> [--allow <file>] <log>...
    skips.py --self-test
"""

import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOW = os.path.join(HERE, "..", "test-skips.txt")

SECTION = re.compile(r"^---- (\S+) stdout ----$")
# The end of a block: the next block, or libtest's lists after them.
END = re.compile(r"^(---- \S+ std(out|err) ----|successes:|failures:|test result: )")


def skipped(lines):
    """(test, reason) for each line starting with `skipped` in a test's block."""
    found = []
    test = None
    for line in lines:
        line = line.rstrip("\r\n")
        m = SECTION.match(line)
        if m:
            test = m.group(1)
            continue
        if END.match(line):
            test = None
            continue
        if test is not None and line.lstrip().startswith("skipped"):
            reason = line.strip()
            if (test, reason) not in found:
                found.append((test, reason))
    return found


def allowed(text, job):
    """The tests the list lets `job` skip: `<job> <test> <why>` per line."""
    names = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            raise ValueError(f"line {n}: '<job> <test> <why>' expected: {line}")
        if parts[0] == job:
            names[parts[1]] = parts[2]
    return names


def check(found, names):
    """The lines to print, and whether every skip was expected."""
    out = []
    ok = True
    for test, reason in found:
        if test in names:
            out.append(f"skipped as expected: {test}: {reason}")
        else:
            ok = False
            out.append(f"::error::skipped, and not in .github/test-skips.txt for this job: {test}: {reason}")
    seen = {t for t, _ in found}
    for test in names:
        if test not in seen:
            out.append(f"::notice::did not skip, though the list allows it: {test}")
    return out, ok


def summary(job, found, names):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a") as f:
        f.write(f"\n#### Skipped tests ({job}): {len(found)}\n\n")
        for test, reason in found:
            mark = "" if test in names else " **(not expected)**"
            f.write(f"- `{test}`: {reason}{mark}\n")


SAMPLE = """\
     Running unittests src/lib.rs (target/debug/deps/nerve_node-0)

running 3 tests
test acl::tests::needs_root ... ok
test exec::tests::limits ... ok
test fs::tests::plain ... ok

successes:

---- acl::tests::needs_root stdout ----
skipped: needs root

---- exec::tests::limits stdout ----
skipped: no systemd-run here

---- fs::tests::plain stdout ----
some output, skipped nothing

successes:
    acl::tests::needs_root
    exec::tests::limits
    fs::tests::plain

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
"""


def self_test():
    found = skipped(SAMPLE.splitlines(True))
    assert found == [
        ("acl::tests::needs_root", "skipped: needs root"),
        ("exec::tests::limits", "skipped: no systemd-run here"),
    ], found
    names = allowed("# job test why\nlinux acl::tests::needs_root needs root\nwindows exec::tests::limits x\n", "linux")
    assert names == {"acl::tests::needs_root": "needs root"}, names
    out, ok = check(found, names)
    assert not ok and any("exec::tests::limits" in line and "::error::" in line for line in out), out
    out, ok = check(found, dict(names, **{"exec::tests::limits": "no user session"}))
    assert ok, out
    out, ok = check([], names)
    assert ok and out == ["::notice::did not skip, though the list allows it: acl::tests::needs_root"], out
    try:
        allowed("linux only-two\n", "linux")
        raise AssertionError("a line without a reason was taken")
    except ValueError:
        pass
    print("self-test passed")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--job")
    p.add_argument("--allow", default=ALLOW)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("logs", nargs="*")
    a = p.parse_args()
    if a.self_test:
        self_test()
        return 0
    if not a.job or not a.logs:
        p.error("--job and a log are needed")
    names = allowed(open(a.allow).read(), a.job)
    found = []
    for log in a.logs:
        with open(log, errors="replace") as f:
            found += [s for s in skipped(f) if s not in found]
    out, ok = check(found, names)
    print("\n".join(out) or "no test skipped")
    summary(a.job, found, names)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
