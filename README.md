<!-- This file is only meant to be read on GitHub. It will not be published anywhere. -->
# DFINITY's Rust Agent Repository
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/dfinity-lab/agent-rust/all)


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

## Packages
This repo has multiple packages in its Cargo workspace.

| Package Name | Links | Description |
|---|---|---|
| `ic-agent` | [![README](https://img.shields.io/badge/-README-green)](./tree/next/ic-agent) | The `ic-agent` is a library to talk directly to the Replica. |  
| `ic-types` | [![README](https://img.shields.io/badge/-README-green)](./tree/next/ic-types) | A list of types relevant to talking to the Replica, and building canisters on the Internet Computer. |  
| `ref-tests` | | A package that only exists to run the ic-ref tests with the ic-agent as the connection. |
