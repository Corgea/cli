#!/bin/bash

BUILD_OS="$(uname)"

if [ $BUILD_OS == "Darwin" ]; then
  TARGETS=("aarch64-apple-darwin" "x86_64-apple-darwin")
elif [ $BUILD_OS == "Linux" ]; then
  TARGETS=("aarch64-unknown-linux-gnu" "x86_64-unknown-linux-gnu" "x86_64-pc-windows-gnu")
else
  echo "Are you building from a supported OS? (Darwin/Linux)"
  exit 1
fi

for target in "${TARGETS[@]}"
do
    if [ $BUILD_OS == "Darwin" ]; then
      cargo build -r --target $target
    else
      cross build -r --target $target
    fi

    zip_file_name="corgea-$target.zip"

    # if zip_file_name exists, remove it
    if [ -f $zip_file_name ]; then
        rm $zip_file_name
    fi

    if [ $target == "x86_64-pc-windows-gnu" ]; then
      zip -j $zip_file_name "target/$target/release/corgea.exe"
    else
      zip -j $zip_file_name "target/$target/release/corgea"
    fi
done