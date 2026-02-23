# Platform Packages

Each subdirectory in this folder is a publishable npm package that contains a single prebuilt native Corgea CLI binary.

- `corgea-cli` (the main package) declares these as optional dependencies.
- CI builds the binary for each target platform, stages it under `vendor/<target-triple>/corgea/`, and publishes the package.
- These packages are implementation details and are not intended to be installed directly.
