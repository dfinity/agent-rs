pub(crate) mod hsm;
pub use hsm::{HardwareIdentity, HardwareIdentityError};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
