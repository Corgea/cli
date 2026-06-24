# Changelog

All notable changes to the Corgea CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is a curated changelog. GitHub Releases also carry auto-generated commit
notes; the two surfaces are complementary and never collide.

## [Unreleased]

### Added

- Curated **beta** pre-release channel. Tagging `vX.Y.Z-beta.N` publishes to
  three opt-in channels without disturbing stable users:
  - npm dist-tag `beta` (`npm install -g @corgea/cli@beta`); `latest` never moves.
  - PyPI pre-release, gated behind `pip install --pre corgea-cli`.
  - GitHub Release flagged `prerelease` with a beta disclaimer in the notes.
  Stable installs (`@corgea/cli`, `corgea-cli`) always resolve to the latest
  non-beta release. See [RELEASING.md](RELEASING.md) for the cut procedure.
- Release-version guards: `version-guard` fails a release whose tag and
  `Cargo.toml` version disagree; `version-bump-check` fails a PR whose
  `Cargo.toml` version still matches the latest released tag.

[Unreleased]: https://github.com/Corgea/cli/compare/v1.9.0...HEAD
