#!/usr/bin/env python3
"""The Landlock ABI of this kernel, and whether a CI job may run on it.

    landlock-abi.py [<least ABI>]

Prints the ABI the kernel answers (0 for no Landlock), as the node asks it:
landlock_create_ruleset with the version flag, call 444 on x86_64 and
aarch64. With a least ABI, fails on a kernel with less: the job's Landlock
tests would skip there, so a runner image that loses Landlock fails the job
instead of passing it with less tested. 0 as the least says the machine is
to have no Landlock at all.
"""

import ctypes
import os
import sys

LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1


def abi():
    libc = ctypes.CDLL(None, use_errno=True)
    v = libc.syscall(LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                     ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    return max(v, 0)


def main():
    have = abi()
    print(f"Landlock ABI {have} (kernel {os.uname().release})")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(f"- Landlock ABI {have}, kernel `{os.uname().release}`\n")
    if len(sys.argv) < 2:
        return 0
    least = int(sys.argv[1])
    if least == 0 and have != 0:
        print(f"::error::this machine was to have no Landlock, it has ABI {have}")
        return 1
    if have < least:
        print(f"::error::Landlock ABI {have} here, the job expects at least {least}: the runner's kernel changed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
