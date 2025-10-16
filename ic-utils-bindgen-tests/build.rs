use std::path::PathBuf;

use candid::Principal;
use ic_utils_bindgen::Config;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let base_cfg = dir.join("base.toml");
    let icrc_did = dir.join("icrc1.did");
    Config::new("icrc_runtime", &icrc_did)
        .runtime_callee()
        .set_type_selector_config(&base_cfg)
        .generate();
    Config::new("icrc_static", &icrc_did)
        .static_callee("ryjl3-tyaaa-aaaaa-aaaba-cai".parse::<Principal>().unwrap())
        .set_type_selector_config(&base_cfg)
        .generate();
    Config::new("icrc_types", &icrc_did)
        .set_type_selector_config(&base_cfg)
        .generate();
}
