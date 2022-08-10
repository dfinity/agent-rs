# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ic-asset

* Fixed custom configured HTTP headers - no longer is the header's value wrapped with double quotes.

### ic-agent

* Switched to `miracl_core_bls12381` crate for bls
* Added new `hyper` transport `HyperReplicaV2Transport`

## [0.20.0] - 2022-07-14

### Breaking change: Updated to ic-types 0.4.0

* Remove `PrincipalInner`
  * `Principal` directly holds `len` and `bytes` fields
* `PrincipalError` enum has different set of variants reflecting changes in `from_text` logic.
* `from_text` accepts input containing uppercase letters which results in Err before.
* `from_text` verifies CRC32 check sequence

### ic-asset

Added support configurable inclusion and exclusion of files and directories (including dotfiles and dot directories), done via `.ic-assets.json` config file:
- example of `.ic-assets.json` file format:
  ```
  [
      {
          "match": ".*",
          "cache": {
              "max_age": 20
          },
          "headers": {
              "X-Content-Type-Options": "nosniff"
          },
          "ignore": false
      }
  ]
  ```
- see [PR](https://github.com/dfinity/agent-rs/pull/361) and [tests](https://github.com/dfinity/agent-rs/blob/f8515d1d0825b47c8048f5528ac3b65018065779/ic-asset/src/sync.rs#L145) for more examples

Added support for configuring HTTP headers for assets in asset canister (via `.ic-assets.json` config file):
- example of `.ic-assets.json` file format:
  ```
  [
      {
          "match": "*",
          "cache": {
              "max_age": 20
          },
          "headers": {
              "X-Content-Type-Options": "nosniff"
          }
      },
      {
          "match": "**/*",
          "headers": null
      },
  ]
  ```
- `headers` from multiple applicable rules are being stacked/concatenated, unless `null` is specified, which resets/empties the headers. Both `"headers": {}` and absence of `headers` don't have any effect on end result.

## [0.19.0] - 2022-07-06

### ic-asset

Added support for asset canister config files in `ic-assets`.
- reads configuration from `.ic-assets.json` config files if placed inside assets directory, multiple config files can be used (nested in subdirectories)
- runs successfully only if the config file is right format (valid JSON, valid glob pattern, JSON fields in correct format)
- example of `.ic-assets.json` file format:
  ```
  [
      {
          "match": "*",
          "cache": {
              "max_age": 20
          }
      }
  ]
  ```
- works only during asset creation
- the config file is being taken into account only when calling `ic_asset::sync` (i.e. `dfx deploy` or `icx-asset sync`)

## [0.18.0] - 2022-06-23

### ic-asset

Breaking change: ic-asset::sync() now synchronizes from multiple source directories.

This is to allow for configuration files located alongside assets in asset source directories.

Also, ic-asset::sync:
- skips files and directories that begin with a ".", as dfx does when copying assets to an output directory.
- reports an error if more than one asset file would resolve to the same asset key

## [0.17.1] - 2022-06-22

[agent-rs/349](https://github.com/dfinity/agent-rs/pull/349) feat: add with_max_response_body_size to ReqwestHttpReplicaV2Transport

## [0.17.0] - 2022-05-19

Updated dependencies.  Some had breaking changes: k256 0.11, pkcs 0.9, and sec1 0.3.

Fixed a potential panic in secp256k1 signature generation.

## [0.16.0] - 2022-04-28

Added `ReqwestHttpReplicaV2Transport::create_with_client`.

Remove `openssl` in favor of pure rust libraries.

Updated minimum version of reqwest to 0.11.7.  This is to avoid the following error, seen with reqwest 0.11.6:

```
Unknown TLS backend passed to use_preconfigured_tls
```

Updated wallet interface for 128-bit API.

Remove parameterized canister pattern.  Use `WalletCanister::create` rather than `Wallet::create`.

wallet_send takes Principal instead of &Canister.


## [0.15.0] - 2022-03-28

Updated `ic_utils::interfaces::http_request` structures to use `&str` to reduce copying.

Removed `Deserialize` from `HttpRequest`.

Changed `HttpResponse` to be generic over entire callback instead of just `ArgToken`.

Added `HttpRequestStreamingCallbackAny` to deserialize any callback, regardless of signature.

Added conversion helpers for `HttpResponse`, `StreamingStrategy` and `CallbackStrategy` across generics.

Changes to `Canister<HttpRequestCanister>` interface.

* Made `http_request`, `http_request_update`, and `http_request_stream_callback` more generic and require fewer string copies.
* Added `_custom` variants to enable custom `token` deserialization.

## [0.14.0] - 2022-03-17

Introduced HttpRequestStreamingCallback to work around https://github.com/dfinity/candid/issues/273.

Response certificate verification will check that the canister id falls within the range of valid canister ids for the subnet.

## [0.13.0] - 2022-03-07
Secp256k1 identity now checks if a curve actually uses the secp256k1 parameters. It cannot be used to load non-secp256k1 identities anymore.

Data type of `cycles` changed to `u128` (was `u64`).

fetch_root_key() only fetches on the first call.

Re-genericized Token to allow use of an arbitrary Token type with StreamingStrategy.

## [0.12.1] - 2022-02-09

Renamed BatchOperationKind._Clear to Clear for compatibility with the certified assets canister.
This avoids decode errors, even though the type isn't referenced here.

## [0.12.0] - 2022-02-03

Changed the 'HttpRequest.upgrade' field to 'Option<bool>' from 'bool'.

## [0.11.1] - 2022-01-10

The `lookup_value` function now takes generics which can be iterated over (`IntoIterator<Item = &'p Label>`)  and transformed into a `Vec<Label>`, rather than just a `Vec<Label>`.

## [0.11.0] - 2022-01-07

### Breaking change: Updated to ic-types 0.3.0

The `lookup_path` method now takes an `Iterator<Label>` rather than an `AsRef<[Label]>`

## [0.10.2] - 2021-12-22

### ic-agent

Added support for upgrading HTTP requests (http_request_update method)

## [0.10.1] - 2021-12-10

Updated crate dependencies, most notably updating rustls,
removing the direct dependency on webpki-roots, and allowing
consumers of ic-agent to update to reqwest 0.11.7.

### ic-agent

#### Added: read_state_canister_metadata

Implements https://github.com/dfinity-lab/ic-ref/pull/371

### ic-asset

#### Fixed: sync and upload will now attempt retries as expected

Fixed a defect in asset synchronization where no retries would be attempted after the first 30 seconds overall.

### icx-asset

#### Fixed: now works with secp256k1 .pem files.

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
