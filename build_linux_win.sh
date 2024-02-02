#!/bin/bash

cross build -r --target x86_64-pc-windows-gnu
cross build -r --target x86_64-unknown-linux-gnu
cross build -r --target aarch64-unknown-linux-gnu

zip corgea-aarch64-unkown-linux-gnu.zip target/aarch64-unknown-linux-gnu/release/corgea
zip corgea-x86_64-unknown-linux-gnu.zip target/x86_64-unknown-linux-gnu/release/corgea
zip corgea-x86_64-pc-windows-gnu.zip target/x86_64-pc-windows-gnu/release/corgea.exe