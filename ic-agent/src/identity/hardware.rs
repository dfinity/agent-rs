use crate::{Identity, Signature};
use ic_types::Principal;

use pkcs11::Ctx;
use std::path::Path;
use thiserror::Error;
use pkcs11::types::{CKF_SERIAL_SESSION, CK_SESSION_HANDLE, CK_ATTRIBUTE, CKA_ID};

/// An error happened while reading a PEM file to create a BasicIdentity.
#[derive(Error, Debug)]
pub enum HardwareIdentityError {
    #[error(transparent)]
    Wrapped(#[from] pkcs11::errors::Error),
}

/// An identity based on an HSM
pub struct HardwareIdentity {
    slot: u16,
    key_id: String,
    ctx: Ctx,
    session_handle: CK_SESSION_HANDLE,
}

impl HardwareIdentity {
    // /usr/local/lib/opensc-pkcs11.s
    fn new<P>(filename: P, xkey_id: String) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
    {
        let ctx = Ctx::new_and_initialize(filename)?;

        // equivalent of
        //    pkcs11-tool -r --slot $SLOT -y pubkey -d $KEY_ID > public_key.der
        // '-r'  read_object()
        // --slot $SLOT  opt_slot=int, opt_slot_set=1
        // -y pubkey     opt_object_class = CKO_PUBLIC_KEY;
        // -d $KEY_ID    opt_object_id opt_object_id_len
        let slot_id = 0;
        let flags = CKF_SERIAL_SESSION;
        let application = None;
        let notify = None;
        let session_handle = ctx.open_session(slot_id, flags, application, notify)?;
        //ctx.close_session(session_handle)?;
        let key_id = b"\xab\xcd\xef";
        let attributes = [CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id)];
        ctx.find_objects_init(session_handle, &attributes)?;
        let object_handles = ctx.find_objects(session_handle, 1)?;
        let object_handle = object_handles[0];
        ctx.find_objects_final(session_handle)?;

        Ok(HardwareIdentity {
            slot: 0,
            key_id: xkey_id,
            ctx,
            session_handle,
        })
    }
}

impl Drop for HardwareIdentity {
    fn drop(&mut self) {
        self.ctx.close_session(self.session_handle);
    }
}
impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        panic!("no");
        //Ok(Principal::self_authenticating(&self.key_pair.public_key()))
    }
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        panic!("ok");
        // let signature = self.key_pair.sign(msg.as_ref());
        // // At this point we shall validate the signature in this first
        // // skeleton version.
        // let public_key_bytes = self.key_pair.public_key();
        //
        // Ok(Signature {
        //     signature: signature.as_ref().to_vec(),
        //     public_key: public_key_bytes.as_ref().to_vec(),
        // })
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::HardwareIdentity;

    #[test]
    fn it_works() {
        let hid = HardwareIdentity::new(
            "/usr/local/lib/opensc-pkcs11.so".to_string(),
            "abcdef".to_string(),
        )
        .unwrap();
        assert_eq!(2 + 2, 4);
    }
}
