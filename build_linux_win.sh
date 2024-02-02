#!/bin/bash

cross build -r --target x86_64-pc-windows-gnu
cross build -r --target x86_64-unknown-linux-gnu
cross build -r --target aarch64-unknown-linux-gnu