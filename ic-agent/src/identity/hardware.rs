use crate::{Identity, Signature};
use ic_types::Principal;

use openssl_sys::EC_KEY_new;
use pkcs11::types::{
    CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_SERIAL_SESSION, CKK_EC,
    CKO_PUBLIC_KEY, CK_ATTRIBUTE, CK_KEY_TYPE, CK_SESSION_HANDLE,
};
use pkcs11::Ctx;
use simple_asn1::ASN1Block::OctetString;
use simple_asn1::{from_der, ASN1DecodeErr};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// An error happened while reading a PEM file to create a BasicIdentity.
#[derive(Error, Debug)]
pub enum HardwareIdentityError {
    #[error(transparent)]
    PKCS11(#[from] pkcs11::errors::Error),
    // huh?
    // no method named `as_dyn_error` found for reference `&simple_asn1::ASN1DecodeErr` in the current scope
    //#[error("ASN decode error {}", .0.display())]
    //ASN1Decode(#[from] ASN1DecodeErr),
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
        let object_class = CKO_PUBLIC_KEY;
        let attributes = [
            CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id),
            CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_class),
        ];
        ctx.find_objects_init(session_handle, &attributes)?;
        let object_handles = ctx.find_objects(session_handle, 1)?;
        let object_handle = object_handles[0];
        ctx.find_objects_final(session_handle)?;
        let mut kt: CK_KEY_TYPE = 0;
        let mut attribute_types = vec![CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&kt)];
        let (kt_rv, key_types) =
            ctx.get_attribute_value(session_handle, object_handle, &mut attribute_types)?;
        let key_type = key_types[0];
        if kt == CKK_EC {
            println!("yay!");
            let mut ec_point_length_attrs = vec![CK_ATTRIBUTE::new(CKA_EC_POINT)];
            let (rv, ec_point_lengths) =
                ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_length_attrs)?;
            let first = ec_point_lengths[0];
            let mut ec_point = vec![1, 2, 3];
            ec_point.resize(first.ulValueLen as usize, 0);
            let mut ec_point_attrs =
                vec![CK_ATTRIBUTE::new(CKA_EC_POINT).with_bytes(ec_point.as_slice())];
            let (rv, ec_points) =
                ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_attrs)?;
            let fd = from_der(ec_point.as_slice()).expect("der decode failed");
            let fd0 = &fd[0];
            if let OctetString(size, data) = fd0 {
                // this fails:
                //let d2 = from_der(data.as_slice()).expect("der decode(2) failed");

                let mut file = File::create("/Users/ericswanson/key.der").unwrap();

                // Write a slice of bytes to the file
                file.write_all(data.as_slice()).unwrap();
            }

            // {
            //     let mut file = File::create("/Users/ericswanson/key.der").unwrap();
            //
            //     // Write a slice of bytes to the file
            //     file.write_all(ec_point.as_slice()).unwrap();
            // }

            println!("what now");
        }
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
