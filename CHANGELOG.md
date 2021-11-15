# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2021-11-15

Unified all version numbers and removed the zzz-release tool.

### ic-agent

#### Fixed: rewrite all *.ic0.app domains to ic0.app to avoid redirects.

### icx-cert

#### New feature: Add --accept-encoding parameter

It's now possible to specify which encodings will be accepted.  The default (and previous) behavior
is to accept only the identity encoding.  Specifying encodings that browsers more commonly accept
demonstrates the difference in the returned data and certificate.

For example, here is the data and certificate returned when only accepting the identity encoding.

```
$ cargo run -p icx-cert -- print 'http://localhost:8000/index.js?canisterId=ryjl3-tyaaa-aaaaa-aaaba-cai'
DATA HASH: 1495cd574831c23b4db97bc3860666ea495386f0ef0dab73c23ef31db5aa2765
    Label("/index.js", Leaf(0x1495cd574831c23b4db97bc3860666ea495386f0ef0dab73c23ef31db5aa2765)),
```

Here is an example accepting the gzip encoding (as most browsers do), showing that the canister
responded with different data having a different data hash.

```
$ cargo run -p icx-cert -- print --accept-encoding gzip 'http://localhost:8000/index.js?canisterId=ryjl3-tyaaa-aaaaa-aaaba-cai'
DATA HASH: 1770e76af0816ba951320c03eab1263c43de7ac4b0558dd9049cc532b7d6cd01
    Label("/index.js", Leaf(0x1495cd574831c23b4db97bc3860666ea495386f0ef0dab73c23ef31db5aa2765)),
```

### icx-proxy

This project moved to https://github.com/dfinity/icx-proxy.

## [0.9.0] - 2021-10-06

### ic-agent

#### Added

- Added field `replica_health_status` to `Status`.
    - typical values
        - `healthy`
        - `waiting_for_certified_state`
