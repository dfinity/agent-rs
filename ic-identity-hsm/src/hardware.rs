use ic_agent::{Identity, Signature};
use ic_types::Principal;

use num_bigint::BigUint;
use openssl::sha::Sha256;
use pkcs11::types::{CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_LOGIN_REQUIRED, CKF_SERIAL_SESSION, CKK_EC, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKU_USER, CK_ATTRIBUTE, CK_KEY_TYPE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID};
use pkcs11::Ctx;
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, OctetString, Sequence};
use simple_asn1::{from_der, oid, to_der, ASN1DecodeErr, ASN1EncodeErr, OID};
use std::path::Path;
use std::ptr;
use thiserror::Error;

/// An error happened related to a HardwareIdentity.
#[derive(Error, Debug)]
pub enum HardwareIdentityError {
    #[error(transparent)]
    PKCS11(#[from] pkcs11::errors::Error),

    #[error("ASN decode error {0}")]
    ASN1Decode(ASN1DecodeErr),

    #[error(transparent)]
    ASN1Encode(#[from] ASN1EncodeErr),

    #[error(transparent)]
    KeyIdDecode(#[from] hex::FromHexError),
}

/// An identity based on an HSM
pub struct HardwareIdentity {
    key_id: Vec<u8>,
    ctx: Ctx,
    session_handle: CK_SESSION_HANDLE,
    logged_in: bool,
    public_key: Vec<u8>,
}

impl HardwareIdentity {
    /// Create an identity using a specific key on an HSM.
    // /usr/local/lib/opensc-pkcs11.s
    pub fn new<P>(
        filename: P,
        slot_id: u64,
        key_id: String,
        pin: String,
    ) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
    {
        let ctx = Ctx::new_and_initialize(filename)?;
        let session_handle = open_session(&ctx, slot_id)?;
        let logged_in = login_if_required(&ctx, session_handle, &pin)?;
        let key_id = key_id_to_bytes(&key_id)?;
        let public_key = get_public_key(&ctx, session_handle, &key_id)?;

        Ok(HardwareIdentity {
            key_id,
            ctx,
            session_handle,
            logged_in,
            public_key,
        })
    }
}

fn login_if_required(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    pin: &str,
) -> Result<bool, HardwareIdentityError> {
    let token_info = ctx.get_token_info(0)?;
    let login_required = token_info.flags & CKF_LOGIN_REQUIRED != 0;

    if login_required {
        ctx.login(session_handle, CKU_USER, Some(&pin))?;
    }
    Ok(login_required)
}

fn open_session(ctx: &Ctx, slot_id: CK_SLOT_ID) -> Result<CK_SESSION_HANDLE, HardwareIdentityError> {
    // equivalent of
    //    pkcs11-tool -r --slot $SLOT -y pubkey -d $KEY_ID > public_key.der
    // '-r'  read_object()
    // --slot $SLOT  opt_slot=int, opt_slot_set=1
    // -y pubkey     opt_object_class = CKO_PUBLIC_KEY;
    // -d $KEY_ID    opt_object_id opt_object_id_len
    let flags = CKF_SERIAL_SESSION;
    let application = None;
    let notify = None;
    let session_handle = ctx.open_session(slot_id, flags, application, notify)?;
    Ok(session_handle)
}

fn get_public_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &[u8],
) -> Result<Vec<u8>, HardwareIdentityError> {
    //let key_id = b"\xab\xcd\xef";
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
    if kt != CKK_EC {
        unimplemented!("wrong key type");
    }
    println!("yay!");
    let expected = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    let ec_params = get_ec_params(&ctx, session_handle, object_handle)?;
    if ec_params != expected {
        unimplemented!("oh no");
    }
    let mut ec_point = get_ec_point(&ctx, session_handle, object_handle)?;

    let oid_ecdsa = oid!(1, 2, 840, 10045, 2, 1);
    let oid_curve_secp256r1 = oid!(1, 2, 840, 10045, 3, 1, 7);
    let ec_param = Sequence(
        0,
        vec![
            ObjectIdentifier(0, oid_ecdsa),
            ObjectIdentifier(0, oid_curve_secp256r1),
        ],
    );
    let ec_point = BitString(0, ec_point.len() * 8, ec_point);
    let public_key = Sequence(0, vec![ec_param, ec_point]);
    let der = to_der(&public_key)?;
    Ok(der)
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
    let mut ec_params = vec![];
    ec_params.resize(first.ulValueLen as usize, 0);
    let mut attrs = vec![CK_ATTRIBUTE::new(CKA_EC_PARAMS).with_bytes(ec_params.as_slice())];
    let (rv, xxx) = ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    let ff = xxx[0];
    Ok(ec_params)
}

fn get_private_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &[u8],
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    // let key_id = b"\xab\xcd\xef";
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

fn key_id_to_bytes(s: &str) -> Result<Vec<u8>, HardwareIdentityError> {
    let bytes = hex::decode(s)?;
    Ok(bytes)
}

impl Drop for HardwareIdentity {
    fn drop(&mut self) {
        if self.logged_in {
            // necessary? probably not
            self.ctx.logout(self.session_handle).unwrap();
        }
        self.ctx.close_session(self.session_handle).unwrap();
    }
}
impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        let mut sha256 = Sha256::new();
        sha256.update(msg);
        let hash = sha256.finish();
        let private_key_handle = get_private_key_handle(&self.ctx, self.session_handle, &self.key_id)
            .map_err(|e| format!("Failed to get private key handle: {}", e))?;

        let mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.ctx
            .sign_init(self.session_handle, &mechanism, private_key_handle)
            .map_err(|e| format!("Failed to initialize signature: {}", e))?;
        let signature = self
            .ctx
            .sign(self.session_handle, &hash)
            .map_err(|e| format!("Failed to generate signature: {}", e))?;

        Ok(Signature {
            public_key: self.public_key.clone(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::HardwareIdentity;
    use crate::hardware::key_id_to_bytes;

    #[test]
    fn it_works() {
        let hid = HardwareIdentity::new(
            "/usr/local/lib/opensc-pkcs11.so".to_string(),
            0,
            "abcdef".to_string(),
            "837235".to_string(),
        )
        .unwrap();
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn key_id_conversion_successful() {
        let key_id_v = key_id_to_bytes("a53f61e3").unwrap();
        assert_eq!(key_id_v, vec![0xa5, 0x3f, 0x61, 0xe3]);
    }
}
