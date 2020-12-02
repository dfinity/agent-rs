use crate::{Identity, Signature};
use ic_types::Principal;

//use openssl_sys::EC_KEY_new;
use num_bigint::BigUint;
use pkcs11::types::{
    CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_LOGIN_REQUIRED,
    CKF_SERIAL_SESSION, CKK_EC, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKU_USER, CK_ATTRIBUTE,
    CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_SESSION_HANDLE,
};
use pkcs11::Ctx;
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, OctetString, Sequence};
use simple_asn1::{from_der, to_der, OID};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::ptr;
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
    public_key: Vec<u8>,
}

impl HardwareIdentity {
    // /usr/local/lib/opensc-pkcs11.s
    pub fn new<P>(filename: P, xkey_id: String) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
    {
        let ctx = Ctx::new_and_initialize(filename)?;

        let session_handle = open_session(&ctx)?;

        let public_key = get_public_key(&ctx, session_handle)?;

        Ok(HardwareIdentity {
            slot: 0,
            key_id: xkey_id,
            ctx,
            session_handle,
            public_key,
        })
    }
}

fn open_session(ctx: &Ctx) -> Result<CK_SESSION_HANDLE, HardwareIdentityError> {
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
    Ok(session_handle)
}

fn get_public_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
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
        let ec_params = get_ec_params(&ctx, session_handle, object_handle)?;
        let mut ec_point = get_ec_point(&ctx, session_handle, object_handle)?;

        let bytes = vec![
            0x06_u8, 0x07_u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8,
        ];
        let y = from_der(&bytes).unwrap();
        let yy = &y[0];
        if let ObjectIdentifier(usize, oid) = yy {
            println!("oid bytes are {:?}", oid);
        }

        let bytes = vec![
            0x06_u8, 0x08_u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x03u8, 0x01u8, 0x07u8,
        ];
        let y = from_der(&bytes).unwrap();
        let yy = &y[0];
        if let ObjectIdentifier(usize, oid) = yy {
            println!("oid bytes are {:?}", oid);
        }

        // 2a8648ce3d0201 — ECDSA
        let oid_ecdsa = OID::new(vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(840u32),
            BigUint::from(10045u32),
            BigUint::from(2u32),
            BigUint::from(1u32),
        ]);
        // 2a8648ce3d030107 — curve secp256r1
        let oid_curve_secp256r1 = OID::new(vec![
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(840u32),
            BigUint::from(10045u32),
            BigUint::from(3u32),
            BigUint::from(1u32),
            BigUint::from(7u32),
        ]);
        let ec_param = Sequence(
            0,
            vec![
                ObjectIdentifier(0, oid_ecdsa),
                ObjectIdentifier(0, oid_curve_secp256r1),
            ],
        );
        //let mut ec_point_bytes = vec![0u8]; // 0 means "no padding"
        //ec_point_bytes.append(&mut ec_point);
        let ec_point = BitString(0, ec_point.len() * 8, ec_point);
        let public_key = Sequence(0, vec![ec_param, ec_point]);
        let der = to_der(&public_key).unwrap();
        {
            let mut file = File::create("/Users/ericswanson/key.der").unwrap();

            // Write a slice of bytes to the file
            file.write_all(der.as_slice()).unwrap();
        }

        println!("what now");
        Ok(der)
    } else {
        unimplemented!("xxx");
    }
}

fn get_ec_point(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let mut ec_point_length_attrs = vec![CK_ATTRIBUTE::new(CKA_EC_POINT)];
    let (_rv, ec_point_lengths) =
        ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_length_attrs)?;
    let first = ec_point_lengths[0];
    let mut ec_point = vec![1, 2, 3];
    ec_point.resize(first.ulValueLen as usize, 0);
    let mut ec_point_attrs = vec![CK_ATTRIBUTE::new(CKA_EC_POINT).with_bytes(ec_point.as_slice())];
    let (_rv, _ec_points) =
        ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_attrs)?;
    let fd = from_der(ec_point.as_slice()).expect("der decode failed");
    let fd0 = &fd[0];
    if let OctetString(size, data) = fd0 {
        // this fails:
        //let d2 = from_der(data.as_slice()).expect("der decode(2) failed");

        //let mut file = File::create("/Users/ericswanson/key.der").unwrap();

        // Write a slice of bytes to the file
        //file.write_all(data.as_slice()).unwrap();
        Ok(data.clone())
    } else {
        unimplemented!("oh no");
    }
}

fn get_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let mut attrs = vec![CK_ATTRIBUTE::new(CKA_EC_PARAMS)];
    let (rv, ec_params_lengths) =
        ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    let first = ec_params_lengths[0];
    let mut ec_params = vec![1_u8, 2, 3];
    ec_params.resize(first.ulValueLen as usize, 0);
    let mut attrs = vec![CK_ATTRIBUTE::new(CKA_EC_PARAMS).with_bytes(ec_params.as_slice())];
    let (rv, xxx) = ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    let ff = xxx[0];
    Ok(ec_params)
}

fn get_private_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    let key_id = b"\xab\xcd\xef";
    let object_class = CKO_PRIVATE_KEY;
    let attributes = [
        CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id),
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_class),
    ];
    ctx.find_objects_init(session_handle, &attributes)?;
    let object_handles = ctx.find_objects(session_handle, 1)?;
    let object_handle = object_handles[0];
    ctx.find_objects_final(session_handle)?;
    Ok(object_handle)
}

impl Drop for HardwareIdentity {
    fn drop(&mut self) {
        self.ctx.close_session(self.session_handle).unwrap();
    }
}
impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        let token_info = self.ctx.get_token_info(0);
        let token_info = token_info.unwrap();
        if token_info.flags & CKF_LOGIN_REQUIRED != 0 {
            println!("login required");
            let pin = "837235";
            let r = self
                .ctx
                .login(self.session_handle, CKU_USER, Some("837235"));
            r.unwrap();
        }
        let private_key_handle = get_private_key_handle(&self.ctx, self.session_handle);
        let private_key_handle = private_key_handle.unwrap();
        //let mechanism = get_mechanism(&self.ctx, CKM_ECDSA)?;
        let mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let sign_init = self
            .ctx
            .sign_init(self.session_handle, &mechanism, private_key_handle);
        sign_init.unwrap();
        let sig = self.ctx.sign(self.session_handle, msg);
        let sig = sig.unwrap();
        //let sig_fin = self.ctx.sign_final(self.session_handle);
        //let sig_fin = sig_fin.unwrap();

        Ok(Signature {
            signature: sig,
            public_key: self.public_key.clone(),
        })
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

fn get_mechanism(
    ctx: &Ctx,
    mechanism_type: CK_MECHANISM_TYPE,
) -> Result<CK_MECHANISM, HardwareIdentityError> {
    //    ctx.get_mechanism_list()
    //        ctx.get_mechanism_info()
    unimplemented!()
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
