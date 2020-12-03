pub(crate) mod hardware;
pub use hardware::{HardwareIdentity, HardwareIdentityError};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
