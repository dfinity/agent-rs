This is a convenience copy of the code in https://github.com/miracl/core
produced from revision 9138019b73abe369b4ed8ac050d1da90b7d35c87 with these steps:

* `cd rust/`
* `python3 config64.py`
* Select BLS12381 (enter 31, then enter 0)
* Copy the files listed under `core/src` to this directory.
* Remove `main.rs`; Rename `lib.rs` to `mod.rs`.
* `sed -i .bak 's/crate::/crate::bls::/g' *.rs`
* Patch the `bls12381/` directory as follows:
  * `ecp.rs`: Set `ALLOW_ALT_COMPRESS` to true
  * `bls.rs`: Change the domain separator to `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` (in `bls_hash_to_point` function)
  * `bls.rs`: Do not use the "new multi-pairing mechanism", but the alternative in `core_verify` function. 
  (The commented code is out dated. We need the following patch before master fix it)
  ```
        //.. or alternatively
        let g = ECP2::generator();
        let mut v = pair::ate2(&g, &d, &pk, &hm);
  ```
