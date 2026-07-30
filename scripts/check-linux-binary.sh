#!/usr/bin/env bash
#
# Gate on the runtime requirements of a released Linux binary.
#
# Linking against the build runner's glibc stamps that version into the ELF
# version-need table, and the loader refuses the binary on any host with an
# older glibc. Runner images move forward on their own schedule, so without
# this check the supported floor silently follows them.
#
#   scripts/check-linux-binary.sh <binary> <target-triple>
#
# GLIBC_FLOOR (default 2.17) is the highest glibc version a *-gnu binary may
# require. *-musl binaries must be fully static instead.

set -euo pipefail

binary=${1:-}
triple=${2:-}
floor=${GLIBC_FLOOR:-2.17}

if [ -z "$binary" ] || [ -z "$triple" ]; then
  echo "usage: $0 <binary> <target-triple>" >&2
  exit 2
fi

if [ ! -f "$binary" ]; then
  echo "FAIL: $binary does not exist" >&2
  exit 1
fi

case "$triple" in
  aarch64-*) want_machine="AArch64" ;;
  x86_64-*) want_machine="X86-64" ;;
  *)
    echo "FAIL: unsupported target triple: $triple" >&2
    exit 1
    ;;
esac

machine=$(readelf -h "$binary" | sed -n 's/^ *Machine: *//p')
case "$machine" in
  *"$want_machine"*) ;;
  *)
    echo "FAIL: $binary is '$machine', expected $want_machine for $triple" >&2
    exit 1
    ;;
esac

case "$triple" in
  *-musl)
    if readelf -lW "$binary" | grep -q INTERP; then
      echo "FAIL: $binary is dynamically linked; musl builds must be static" >&2
      exit 1
    fi
    echo "OK: $binary ($triple) is statically linked"
    ;;

  *-gnu)
    # A binary with no versioned glibc references is fine, but grep exits 1 on
    # no match, so run it outside the pipeline that feeds the assignment.
    # Requiring a digit keeps unversioned tags such as GLIBC_PRIVATE out.
    version_info=$(readelf -V "$binary")
    needed=$(grep -oE 'GLIBC_[0-9]+(\.[0-9]+)*' <<<"$version_info" | sed 's/^GLIBC_//' | sort -uV || true)

    if [ -z "$needed" ]; then
      echo "OK: $binary ($triple) requires no versioned glibc symbols"
      exit 0
    fi

    highest=$(echo "$needed" | tail -1)
    if [ "$(printf '%s\n%s\n' "$highest" "$floor" | sort -V | tail -1)" != "$floor" ]; then
      echo "FAIL: $binary requires glibc $highest, above the $floor floor" >&2
      echo "      versions required: $(echo "$needed" | tr '\n' ' ')" >&2
      exit 1
    fi

    echo "OK: $binary ($triple) requires at most glibc $highest (floor $floor)"
    ;;

  *)
    echo "FAIL: unsupported libc in target triple: $triple" >&2
    exit 1
    ;;
esac
