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

## Testing
There are two suites of tests that can be executed from this repo; the regular cargo tests and
the ic-ref tests. In order to run the ic-ref tests, you will need a running local reference
server. If you do not have one, those tests will be ignored.

## Release Script
Using the `zzz-release` binary here (not available on crates.io), one can automatically update
the versions of packages based on the Git history. For example, any commit that starts with
`feat:` will update the minor version of packages which files were changed. Commits starting
with `fix:` or which dependencies were changed will update their patch version.

To run, simply do

```sh
cargo run zzz-release
```

If there are any errors (e.g. the workspace is modified locally), an error will be given. Otherwise
by default a git commit will be made, which needs to be pushed (and a PR created).

## Packages
This repo has multiple packages in its Cargo workspace.

| Package Name | Links | Description |
|---|---|---|
| `ic-agent` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/ic-agent) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://docs.rs/ic_agent) | The `ic-agent` is a library to talk directly to the Replica. |  
| `ic-types` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/ic-types) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://docs.rs/ic_types) | A list of types relevant to talking to the Replica, and building canisters on the Internet Computer. |  
| `ic-utils` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/ic-types) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://docs.rs/ic_utils) | A library of utilities for managing calls and canisters. |  
| `icx` | [![README](https://img.shields.io/badge/-README-green)](https://github.com/dfinity/agent-rs/tree/next/icx) | A command line utility to use the agent. Not meant to be published, only available in this repo for tests. |
| `ref-tests` | | A package that only exists to run the ic-ref tests with the ic-agent as the connection. |
