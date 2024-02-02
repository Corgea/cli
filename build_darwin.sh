#!/bin/bash

cargo build -r --target aarch64-apple-darwin
cargo build -r --target x86_64-apple-darwin

zip corgea-aarch64-apple-darwin.zip target/aarch64-apple-darwin/release/corgea
zip corgea-x86_64-apple-darwin.zip target/x86_64-apple-darwin/release/corgea
