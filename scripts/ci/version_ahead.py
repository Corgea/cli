#!/usr/bin/env python3
"""Exit 0 iff the first SemVer argument is strictly greater than the second.

Used by the `version-bump-check` CI job to assert that Cargo.toml has moved
*past* the last released tag. Plain `sort -V` is not SemVer-correct for
pre-releases (it ranks `1.10.0-beta.1` above `1.10.0`), which would wrongly
block the beta -> final transition; this implements SemVer 2.0.0 precedence.

Build metadata (`+...`) is ignored. A version without a pre-release outranks the
same core version with one. Pre-release identifiers compare dot-by-dot: numeric
identifiers rank below alphanumeric ones, numerics compare as integers, and a
longer set of identifiers outranks a shorter prefix.
"""
import sys


def precedence_key(version):
    version = version.split("+", 1)[0]
    core, _, pre = version.partition("-")
    nums = [int(part) for part in core.split(".")]
    while len(nums) < 3:
        nums.append(0)
    if not pre:
        # No pre-release ranks above any pre-release of the same core version.
        return (nums, (1,))
    identifiers = []
    for ident in pre.split("."):
        if ident.isdigit():
            identifiers.append((0, int(ident), ""))
        else:
            identifiers.append((1, 0, ident))
    return (nums, (0, identifiers))


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <candidate> <baseline>", file=sys.stderr)
        return 2
    candidate, baseline = argv[1], argv[2]
    if precedence_key(candidate) > precedence_key(baseline):
        print(f"OK: {candidate} is ahead of {baseline}.")
        return 0
    print(
        f"::error file=Cargo.toml::Cargo.toml version {candidate} is not ahead of "
        f"the last release ({baseline}). Bump [package].version before merging.",
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
