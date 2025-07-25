
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.41.1] - 2025-07-10

* Add canister snapshot download and upload methods to `ManagementCanister`.

## [0.40.1] - 2025-05-15

* Add `read_state_canister_controllers` and `read_state_canister_module_hash` functions.

## [0.40.0] - 2025-03-17

* BREAKING: Added data about the rejected call to CertifiedReject/UncertifiedReject.
* Updated the serialization of `WasmMemoryPersistence`.
* BREAKING: `AgentBuilder::with_background_dynamic_routing` is no longer `async`.
* Extended `RouteProvider` trait with `fn routes_stats()`, returning the number of total and healthy routes.
* Added `set_k_top_nodes` configuration option to `LatencyRoutingSnapshot` that enables selective routing to only `k` API boundary nodes with best ranking (based on latencies and availabilities).

## [0.39.3] - 2025-01-21

* Added `wasm_memory_threshold` field to `CanisterSettings`.

* Added `CanisterInfo` to `MgmtMethod`.

## [0.39.2] - 2024-12-20

* Bumped `ic-certification` to `3.0.0`.

## [0.39.0]

* The lower-level update call functions now return the certificate in addition to the parsed response data.
* Make ingress_expiry required and set the default value to 3 min.
* Changed `BasicIdentity`'s implementation from `ring` to `ed25519-consensus`.
* Added `AgentBuilder::with_max_polling_time` to config the maximum time to wait for a response from the replica.
* `DelegatedIdentity::new` now checks the delegation chain. The old behavior is available under `new_unchecked`.

## [0.38.2] - 2024-09-30

* Limited the number of HTTP 429 retries. Users receiving this error should configure `with_max_concurrent_requests`.
* Added `Envelope::encode_bytes` and `Query/UpdateBuilder::into_envelope` for external signing workflows.
* Added `AgentBuilder::with_arc_http_middleware` for `Transport`-like functionality at the level of HTTP requests.
* Add support for dynamic routing based on boundary node discovery. This is an internal feature for now, with a feature flag `_internal_dynamic-routing`.

## [0.38.1] - 2024-09-23

* Fix `ic-agent` manifest so that documentation can be built for docs.rs.

## [0.38.0] - 2024-09-20

* Breaking: Removed `Transport` and the `hyper` and `reqwest` features. `ReqwestTransport` is now the default and `HyperTransport` has been removed. Existing `ReqwestTransport` functions have been moved to `AgentBuilder`.
* `Url` now implements `RouteProvider`.
* Add canister snapshot methods to `ManagementCanister`.
* Add `AllowedViewers` to `LogVisibility` enum.
* Remove the cargo feature, `experimental_sync_call`, and enable synchronous update calls by default.

## [0.37.1] - 2024-07-25

* Bug fix: Add `api/v2` prefix to read_state requests for hyper transport

## [0.37.0] - 2024-07-23

* Removed the Bitcoin query methods from `ManagementCanister`. Users should use `BitcoinCanister` for that.
* Added `BitcoinCanister` to `ic-utils`.
* Upgraded MSRV to 1.75.0.
* Changed `ic_utils::interfaces::management_canister::builders::InstallMode::Upgrade` variant to be `Option<CanisterUpgradeOptions>`:
  * `CanisterUpgradeOptions` is a new struct which covers the new upgrade option: `wasm_memory_persistence: Option<WasmMemoryPersistence>`.
  * `WasmMemoryPersistence` is a new enum which controls Wasm main memory retention on upgrades which has two variants: `Keep` and `Replace`.
* Added an experimental feature, `experimental_sync_call`, to enable synchronous update calls. The feature adds a toggle to the `ReqwestTransport` and `HyperTransport` to enable synchronous update calls.

## [0.36.0] - 2024-06-04

* Added a default request timeout to `ReqwestTransport`.
* Introduced transparent http request retry logic for network-related failures. `ReqwestTransport::with_max_tcp_errors_retries()`, `HyperTransport::with_max_tcp_errors_retries()`.
* Changed the SyncCall and AsyncCall traits to use an associated type for their output instead of a generic parameter.
* Call builders now generally implement `IntoFuture`, allowing `.call_and_wait().await` to be shortened to `.await`.
* Added `log_visibility` to canister creation and canister setting update options.

## [0.35.0] - 2024-05-10

* Added a limit to the concurrent requests an agent will make at once. This should make server-side ratelimiting much rarer to encounter, even when sending a high volume of requests (for example, a large `ic_utils::ManagementCanister::install` call).
* The agent will now automatically retry 429 Too Many Requests responses after a short delay.
* BREAKING: Changed Chunk Store API to conform to the interface specification:
  * `ChunkHash` was changed from `[u8; 32]` to a struct.
  * Return types of `ManagementCanister::stored_chunks()` and `ManagementCanister::upload_chunk()`.
  * Argument type of `ManagementCanister::install_chunked_code()`.
  * `InstallChunkedCodeBuilder`.
    * All occurrences of `storage_canister` were changed to `store_canister`.
    * The field `chunk_hashes_list` was changed from `vec<vec<u8>>` to `vec<ChunkHash>`.
* Changed `WalletCanister::from_canister/create`'s version check to not rely on the reject code.
* Added `QueryBuilder::call_with_verification()` and `QueryBuilder::call_without_verification()` which always/never verify query signatures
  regardless the Agent level configuration from `AgentBuilder::with_verify_query_signatures`.
* Function `Agent::fetch_api_boundary_nodes()` is split into two functions: `fetch_api_boundary_nodes_by_canister_id()` and `fetch_api_boundary_nodes_by_subnet_id()`.
* `ReqwestTransport` and `HyperTransport` structures storing the trait object `route_provider: Box<dyn RouteProvider>` have been modified to allow for shared ownership via `Arc<dyn RouteProvider>`.
* Added `wasm_memory_limit` to canister creation and canister setting update options.
* Bumped Reqwest version from `0.11.7` to `0.12.4`

## [0.34.0] - 2024-03-18

* Changed `AgentError::ReplicaError` to `CertifiedReject` or `UncertifiedReject`. `CertifiedReject`s went through consensus, and `UncertifiedReject`s did not. If your code uses `ReplicaError`:
    * for queries: use `UncertifiedReject` in all cases (for now)
    * for updates: use `CertifiedReject` for errors raised after the message successfully reaches the canister, and `UncertifiedReject` otherwise
* Added `Agent::fetch_api_boundary_nodes` for looking up API boundary nodes in the state tree.
* Timestamps are now being checked in `Agent::verify` and `Agent::verify_for_subnet`. If you were using it with old certificates, increase the expiry timeout to continue to verify them.
* Added node metrics, ECDSA, and Bitcoin functions to `MgmtMethod`. Most do not have wrappers in `ManagementCanister` because only canisters can call these functions.
* Added `FetchCanisterLogs` function to `MgmtMethod` and a corresponding wrapper to `ManagementCanister`.
* Updated the `ring` crate to 0.17.7.  `ring` 0.16 has a bug where it requires incorrect Ed25519 PEM encoding. 0.17.7 fixes that and is backwards compatible.
* Removed serde and candid serialization traits from the `Status` type.
* Added commas and newlines to the `Status` fmt::Display output. It is valid JSON now (it was close before).

## [0.33.0] - 2024-02-08

* Changed the return type of `stored_chunks` to a struct.
* Added a prime256v1-based `Identity` impl to complement the ed25519 and secp256k1 `Identity` impls.
* Changed the type of `InstallMode.skip_pre_upgrade` from `bool` to `Option<bool>` to match the interface specification.

## [0.32.0] - 2024-01-18

* Added the chunked wasm API to ic-utils. Existing code that uses `install_code` should probably update to `install`, which works the same but silently handles large wasm modules.
* Added query stats to `StatusCallResult`.
* Upgraded `ic-certification` to v2.2.

## [0.31.0] - 2023-11-27

* Breaking change: Bump candid to 0.10. Downstream libraries need to bump Candid to 0.10 as well.
* Feat: add `idle_cycles_burned_per_day` field to `StatusCallResult`.

## [0.30.2] - 2023-11-16

* Fixed a spurious certificate validation error in the five minutes after a node is added to a subnet

## [0.30.1] - 2023-11-15

* Fixed `HyperTransport` endpoint construction (`//` in the format `/api/v2//canister/5v3p4-iyaaa-aaaaa-qaaaa-cai/query`)

## [0.30.0] - 2023-11-07

* Added node signature certification to query calls, for protection against rogue boundary nodes. This can be disabled with `with_verify_query_signatures`.
* Added `with_nonce_generation` to `QueryBuilder` for precise cache control.
* Added the ability to dispatch to multiple URLs to `ReqwestTransport` and `HyperTransport`, with a `RouteProvider` trait and a provided `RoundRobinRouteProvider` implementation.
* Added `read_subnet_state_raw` to `Agent` and `read_subnet_state` to `Transport` for looking up raw state by subnet ID instead of canister ID.
* Added `read_state_subnet_metrics` to `Agent` to access subnet metrics, such as total spent cycles.
* Types passed to the `to_request_id` function can now contain nested structs, signed integers, and externally tagged enums.
* `Envelope` struct is public also outside of the crate.
* Remove non-optional `ic_api_version` field (whose value is not meaningfully populated by the replica) and optional `impl_source` and `impl_revision` fields (that are not populated by the replica) from the expected `/api/v2/status` endpoint response.
* Drop `senders` field from user delegations (type `Delegation`).

## [0.29.0] - 2023-09-29

* Added `reserved_cycles_limit` to canister creation and canister setting update options.
* Added `reserved_cycles` and `reserved_cycles_limit` to canister status call result.

## [0.28.0] - 2023-09-21

* Added `DelegatedIdentity`, an `Identity` implementation for consuming delegations such as those from Internet Identity.
* Replica protocol type definitions have been moved to an `ic-transport-types` crate. `ic-agent` still reexports the ones for its API.
* The `Unknown` lookup of a request_status path in a certificate results in an `AgentError` (the IC returns `Absent` for non-existing paths).
* For `Canister` type, added methods with no trailing underscore: update(), query(), canister_id(), clone_with()

## [0.27.0] - 2023-08-30

* Breaking change: Remove argument builder form `ic-utils`. `CallBuilder::with_arg` sets a single argument, instead of pushing a new argument to the list. This function can be called at most once. If it's called multiple times, it panics. If you have multiple arguments, use `CallBuilder::with_args((arg1, arg2))` or `CallBuilder::set_raw_arg(candid::Encode!(arg1, arg2)?)`.
* feat: Added `public_key`, `sign_arbitrary`, `sign_delegation` functions to `Identity`.
* Add `From` trait to coerce `candid::Error` into `ic_agent::AgentError`.
* Add `Agent::set_arc_identity` method to switch identity.

## [0.26.1] - 2023-08-22

Switched from rustls crate to rustls-webpki fork to address https://rustsec.org/advisories/RUSTSEC-2023-0052

## [0.26.0] - 2023-08-21

Removed the `arc_type` feature requirement for candid, in order to avoid deprecation warnings.  This is a breaking change.  The call and call_and_wait are no longer `async fn` and instead return a Future or BoxFuture.

## [0.25.0] - 2023-07-05

* Breaking Change: builders are now owning-style rather than borrowing-style; with_arg takes an owned Vec rather than a borrowed Vec
* Breaking Change: Identity::sign takes &EnvelopeContent rather than the request ID.
* Bump Candid crate to 0.9.0

## [0.24.0] - 2023-05-19

* fix: Adjust the default polling parameters to provide better UX. Remove the `CouldNotReadRootKey` error and panic on poisoned mutex.
* chore: remove deprecated code and fix style
* Breaking Change: removing the PasswordManager
* Breaking Change: Enum variant `AgentError::ReplicaError` is now a tuple struct containing `RejectResponse`.
* Handling rejected update calls where status code is 200. See IC-1462
* Reject code type is changed from `u64` to enum `RejectCode`.

* Support WASM targets in the browser via `wasm-bindgen`. Feature `wasm-bindgen` required.
* Do not send `certificate_version` on HTTP Update requests
* Update `certificate_version` to `u16` instead of `u128`, fixes an issue where the asset canister always responds with v1 response verification

### ic-certification

* Breaking change: Content and path storage has been changed from a `Cow<[u8]>` to a user-provided `T: AsRef<u8>`, removing the lifetime from various types.

### icx-cert

* Fixed issue where a missing request header caused the canister to not respond with an `ic-certificate` header.

## [0.23.2] - 2023-04-21

* Expose the root key to clients through `read_root_key`

## [0.23.1] - 2023-03-09

* Add `lookup_subtree` method to HashTree & HashTreeNode to allow for subtree lookups.
* Derive `Clone` on `Certificate` and `Delegation` structs.
* Add certificate version to http_request canister interface.
* (ic-utils) Add specified_id in provisional_create_canister_with_cycles.

## [0.23.0] - 2022-12-01

* Remove `garcon` from API. Callers can remove the dependency and any usages of it; all waiting functions no longer take a waiter parameter.
* Create `ic-certification` crate and move HashTree and Certificate types.

## [0.22.0] - 2022-10-17

* Drop `disable_range_check` flag from certificate delegation checking.

## [0.21.0] - 2022-10-03

* Update `candid` to v0.8.0.
* Move `hash_tree` from `ic-types` and no more re-export ic-types.

## [0.20.1] - 2022-09-27

* Set `default-features = false` for `ic-agent` interdependencies to reduce unused nested dependencies.
* Bump `candid` to `0.7.18`.

### ic-asset

* Fixed custom configured HTTP headers - no longer is the header's value wrapped with double quotes.

### ic-agent

* Switched to `ic-verify-bls-signature` crate for verify BLS signatures
* Added new `hyper` transport `HyperReplicaV2Transport`
* Added Agent::set_identity method (#379)
* Updated lookup_request_status method to handle proofs of absent paths in certificates.

### ic-utils

* Make it possible to specify effective canister id in CreateCanisterBuilder

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
