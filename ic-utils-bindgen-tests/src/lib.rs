pub mod icrc_runtime {
    include!(concat!(env!("OUT_DIR"), "/icrc_runtime.rs"));
}

pub mod icrc_static {
    include!(concat!(env!("OUT_DIR"), "/icrc_static.rs"));
}

pub mod icrc_types {
    include!(concat!(env!("OUT_DIR"), "/icrc_types.rs"));
}
