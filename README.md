# DFINITY's Rust Agent Repository
![GitHub Workflow Status](https://github.com/dfinity/agent-rs/workflows/Tests/badge.svg)
<!-- This file is only meant to be read on GitHub. It will not be published anywhere. -->


## Contributing
Please follow the guidelines in the [CONTRIBUTING.md](.github/CONTRIBUTING.md) document.

## Building
We use `cargo` to build this repo. Make sure you have rust stable installed. To build the repo:

```sh
cargo build
```

### Rust toolchain and MSRV
Two different Rust versions are in play, and they are deliberately decoupled:

| | Where | Value |
|---|---|---|
| Development toolchain | `rust-toolchain.toml` | `stable` |
| MSRV | `rust-version` in the workspace `Cargo.toml` | pinned |

Development, `cargo fmt`, `cargo clippy` and all CI jobs except one use the
latest **stable** release. The **MSRV** is the oldest compiler the published
crates are guaranteed to build with, and is enforced by the `msrv` job in
[`.github/workflows/test.yml`](.github/workflows/test.yml), which reads the
version out of `Cargo.toml`. That job builds the published crates only — the
MSRV covers building the libraries, not running our test suite, so
dev-dependencies may require a newer compiler.

Consequences worth knowing:

* Bumping the MSRV is a one-line change to `rust-version`. Do it only when we
  need newer Rust features or a dependency forces it, in a minor (not patch)
  release, with a CHANGELOG entry.
* Because clippy tracks stable, a new Rust release can introduce lints that fail
  CI on an otherwise untouched branch. The fix is a small lint-cleanup PR, not an
  MSRV or toolchain change.

## Testing
There are two suites of tests that can be executed from this repo; the regular cargo tests and
the ic-ref tests. In order to run the ic-ref tests, you will need a running local reference
server. If you do not have one, those tests will be ignored.

## Release
To release:
- increase the version number in Cargo.toml (`workspace.package` and `workspace.dependencies`)
- add a header for the version under "## Unreleased" in CHANGELOG.md
- run `cargo build` to update the lock file

## Packages
This repo has multiple packages in its Cargo workspace.

| Package Name | Links | Description |
|---|---|---|
| `ic-agent` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/ic-agent) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://docs.rs/ic_agent) | The `ic-agent` is a library to talk directly to the Replica. |  
| `ic-utils` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/ic-utils) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://docs.rs/ic_utils) | A library of utilities for managing calls and canisters. |  
| `icx` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/icx) | A command line utility to use the agent. Not meant to be published, only available in this repo for tests. |
| `ref-tests` | | A package that only exists to run the ic-ref tests with the ic-agent as the connection. |
