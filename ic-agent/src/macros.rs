macro_rules! impl_debug_empty {
    ($name:ty) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!("? ", stringify!($name)))
            }
        }
    };
}
