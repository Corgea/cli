#!/bin/bash

BUILD_OS="$(uname)"

# Keep in sync with GLIBC_FLOOR in .github/workflows/release-binaries.yml. Linux
# binaries are cross-linked against this floor so they do not pick up whatever
# glibc the build host happens to ship.
GLIBC_FLOOR="${GLIBC_FLOOR:-2.17}"

if [ $BUILD_OS == "Darwin" ]; then
  TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")
elif [ $BUILD_OS == "Linux" ]; then
  TARGETS=("aarch64-unknown-linux-gnu" "aarch64-unknown-linux-musl" "x86_64-unknown-linux-gnu" "x86_64-unknown-linux-musl")

  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "cargo-zigbuild is required to build the Linux targets."
    echo "Install it with: cargo install cargo-zigbuild && pip install ziglang"
    exit 1
  fi
else
  echo "Are you building from a supported OS? (Darwin/Linux)"
  exit 1
fi

for target in "${TARGETS[@]}"
do
    if [ $BUILD_OS == "Darwin" ]; then
      cargo build -r --target $target || exit 1
    else
      build_target="$target"
      if [[ "$target" == *-gnu ]]; then
        build_target="${target}.${GLIBC_FLOOR}"
      fi

      cargo zigbuild -r --target "$build_target" || exit 1
      GLIBC_FLOOR="$GLIBC_FLOOR" \
        ./scripts/check-linux-binary.sh "target/$target/release/corgea" "$target" || exit 1
    fi

    zip_file_name="corgea-$target.zip"

    # if zip_file_name exists, remove it
    if [ -f $zip_file_name ]; then
        rm $zip_file_name
    fi

    zip -j $zip_file_name "target/$target/release/corgea"
done
