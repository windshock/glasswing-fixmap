#!/usr/bin/env python3
"""Differential conformance check for the optional `univers` comparator backend.

Because `univers` drives security decisions when enabled, it is not trusted
blindly. This checks its ordering against a curated corpus whose expected results
are the documented behavior of each ecosystem's authoritative implementation
(RPM `rpmvercmp` epoch/tilde rules, Debian `dpkg --compare-versions`, Apache
Maven `ComparableVersion`, Composer `composer/semver`). Only a scheme that passes
every case is approved for deterministic AFFECTED gating.

Run:  python3 tools/univers-conformance.py   (requires `pip install univers`)
Exit: 0 if every scheme passes, 1 otherwise.
"""
import sys

try:
    from univers.versions import (
        ComposerVersion,
        DebianVersion,
        MavenVersion,
        RpmVersion,
    )
except Exception:
    sys.stderr.write("univers is not installed (pip install univers)\n")
    sys.exit(2)

# (a, b, expected) where expected is the sign of compare(a, b): '<', '=', '>'.
CORPUS = {
    "rpm": (
        RpmVersion,
        [
            ("1.0-1.el8", "1.0-2.el8", "<"),   # release ordering
            ("1.0", "1.0.1", "<"),
            ("1:1.0", "2.0", ">"),             # epoch dominates
            ("1.0~rc1", "1.0", "<"),           # tilde sorts before release
            ("1.0^post1", "1.0", ">"),         # caret sorts after release
            ("2.0", "2.0", "="),
        ],
    ),
    "debian": (
        DebianVersion,
        [
            ("1.0-1", "1.0-2", "<"),
            ("1:1.0", "2.0", ">"),             # epoch dominates
            ("1.0~beta", "1.0", "<"),          # tilde sorts before release
            ("1.0-1ubuntu2", "1.0-1", ">"),
            ("1.0", "1.0", "="),
        ],
    ),
    "maven": (
        MavenVersion,
        [
            ("1.0", "1.1", "<"),
            ("1.0-alpha", "1.0-beta", "<"),
            ("1.0-alpha", "1.0", "<"),         # qualifier before release
            ("1.0-SNAPSHOT", "1.0", "<"),
            ("2.0", "2.0", "="),
        ],
    ),
    "composer": (
        ComposerVersion,
        [
            ("1.0.0", "1.0.1", "<"),
            ("1.0.0-alpha", "1.0.0", "<"),
            ("1.0.0", "1.1.0", "<"),
            ("2.0.0", "2.0.0", "="),
        ],
    ),
}


def sign(version_class, a, b):
    x, y = version_class(a), version_class(b)
    return "<" if x < y else (">" if x > y else "=")


def main():
    all_pass = True
    for scheme, (version_class, cases) in CORPUS.items():
        failures = []
        for a, b, expected in cases:
            try:
                got = sign(version_class, a, b)
            except Exception as error:  # noqa: BLE001
                got = f"error:{error}"
            if got != expected:
                failures.append(f"    {a} vs {b}: expected {expected}, got {got}")
        status = "PASS" if not failures else "FAIL"
        print(f"{scheme}: {status} ({len(cases)} cases)")
        for line in failures:
            print(line)
        all_pass = all_pass and not failures
    print("\nConformance-approved for gating:", "all schemes" if all_pass else "NOT all schemes")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
