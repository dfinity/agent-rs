use ic_agent::{Identity, Signature};
use ic_types::Principal;

use num_bigint::BigUint;
use openssl::sha::Sha256;
use pkcs11::types::{
    CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_LOGIN_REQUIRED,
    CKF_SERIAL_SESSION, CKK_EC, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_OK, CKU_USER,
    CK_ATTRIBUTE, CK_KEY_TYPE, CK_MECHANISM, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE,
    CK_SLOT_ID,
};
use pkcs11::Ctx;
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, OctetString, Sequence};
use simple_asn1::{from_der, oid, to_der, ASN1DecodeErr, ASN1EncodeErr, OID};
use std::path::Path;
use std::ptr;
use thiserror::Error;

type KeyIdVec = Vec<u8>;
type KeyId = [u8];
type DerPublicKeyVec = Vec<u8>;

/// Type alias for a sha256 result (ie. a u256).
type Sha256Hash = [u8; 32];

// We expect the parameters to be curve secp256r1.  This is the base127 encoded form:
const EXPECTED_EC_PARAMS: &[u8; 10] = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

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

    #[error("Key not found")]
    KeyNotFound,

    #[error("Unexpected key type {0}")]
    UnexpectedKeyType(CK_KEY_TYPE)
}

/// An identity based on an HSM
pub struct HardwareIdentity {
    key_id: KeyIdVec,
    ctx: Ctx,
    session_handle: CK_SESSION_HANDLE,
    logged_in: bool,
    public_key: DerPublicKeyVec,
}

impl HardwareIdentity {
    /// Create an identity using a specific key on an HSM.
    // /usr/local/lib/opensc-pkcs11.s
    pub fn new<P>(
        filename: P,
        slot_id: u64,
        key_id: &str,
        pin: &str,
    ) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
    {
        let ctx = Ctx::new_and_initialize(filename)?;
        let session_handle = open_session(&ctx, slot_id)?;
        let logged_in = login_if_required(&ctx, session_handle, pin, slot_id)?;
        let key_id = str_to_key_id(key_id)?;
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

fn open_session(
    ctx: &Ctx,
    slot_id: CK_SLOT_ID,
) -> Result<CK_SESSION_HANDLE, HardwareIdentityError> {
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

fn login_if_required(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    pin: &str,
    slot_id: CK_SLOT_ID,
) -> Result<bool, HardwareIdentityError> {
    let token_info = ctx.get_token_info(slot_id)?;
    let login_required = token_info.flags & CKF_LOGIN_REQUIRED != 0;

    if login_required {
        ctx.login(session_handle, CKU_USER, Some(&pin))?;
    }
    Ok(login_required)
}

fn get_public_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<DerPublicKeyVec, HardwareIdentityError> {
    let object_handle = get_public_key_handle(&ctx, session_handle, key_id)?;

    validate_key_type(ctx, session_handle, object_handle)?;
    validate_ec_params(ctx, session_handle, object_handle)?;

    let ec_point = get_ec_point(&ctx, session_handle, object_handle)?;

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

fn validate_key_type(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    // This value will be mutated.  `let mut` results in a warning, though.
    let kt: CK_KEY_TYPE = 0;

    let mut attribute_types = vec![CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&kt)];
    let (kt_rv, key_types) =
        ctx.get_attribute_value(session_handle, object_handle, &mut attribute_types)?;
    if kt_rv != CKR_OK {
        unimplemented!("bad kt_rv");
    }
    let key_type = key_types[0];
    if kt != CKK_EC {
        return Err(HardwareIdentityError::UnexpectedKeyType(kt));
    }
    if key_type.get_ck_ulong()? != CKK_EC {
        unimplemented!("wrong key type (key_type)");
    }
    Ok(())
}

// We just want to make sure that the key on the HSM has the expected EC parameters.
fn validate_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    let ec_params = get_ec_params(&ctx, session_handle, object_handle)?;
    if ec_params != EXPECTED_EC_PARAMS {
        unimplemented!("oh no");
    }
    Ok(())
}

fn get_ec_point(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let mut ec_point_length_attrs = vec![CK_ATTRIBUTE::new(CKA_EC_POINT)];
    let (rv, ec_point_lengths) =
        ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_length_attrs)?;
    if rv != CKR_OK {
        unimplemented!("bad kt_rv");
    }
    let first = ec_point_lengths[0];
    let mut ec_point = vec![1, 2, 3];
    ec_point.resize(first.ulValueLen as usize, 0);
    let mut ec_point_attrs = vec![CK_ATTRIBUTE::new(CKA_EC_POINT).with_bytes(ec_point.as_slice())];
    let (rv, _ec_points) =
        ctx.get_attribute_value(session_handle, object_handle, &mut ec_point_attrs)?;
    if rv != CKR_OK {
        unimplemented!("bad kt_rv");
    }

    let fd = from_der(ec_point.as_slice()).expect("der decode failed");
    let fd0 = &fd[0];
    if let OctetString(_size, data) = fd0 {
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
    if rv != CKR_OK {
        unimplemented!("bad kt_rv");
    }
    let first = ec_params_lengths[0];
    let mut ec_params = vec![];
    ec_params.resize(first.ulValueLen as usize, 0);
    let mut attrs = vec![CK_ATTRIBUTE::new(CKA_EC_PARAMS).with_bytes(ec_params.as_slice())];
    let (rv, _attributes) = ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    if rv != CKR_OK {
        unimplemented!("bad kt_rv");
    }
    Ok(ec_params)
}

fn get_public_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_by_key_id(ctx, session_handle, key_id, CKO_PUBLIC_KEY)
}

fn get_private_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &[u8],
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_by_key_id(ctx, session_handle, key_id, CKO_PRIVATE_KEY)
}

fn get_object_handle_by_key_id(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &[u8],
    object_class: CK_OBJECT_CLASS,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    let attributes = [
        CK_ATTRIBUTE::new(CKA_ID).with_bytes(&key_id),
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_class),
    ];
    ctx.find_objects_init(session_handle, &attributes)?;
    let object_handles = ctx.find_objects(session_handle, 1)?;
    let object_handle = *object_handles
        .get(0)
        .ok_or_else(|| HardwareIdentityError::KeyNotFound)?;
    ctx.find_objects_final(session_handle)?;
    Ok(object_handle)
}

// A key id is a sequence of pairs of hex digits, case-insensitive.
fn str_to_key_id(s: &str) -> Result<KeyIdVec, HardwareIdentityError> {
    let bytes = hex::decode(s)?;
    Ok(bytes)
}

impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        let hash = hash_message(msg);
        let signature = self.sign_hash(&hash)?;

        Ok(Signature {
            public_key: self.public_key.clone(),
            signature,
        })
    }
}

fn hash_message(msg: &[u8]) -> Sha256Hash {
    let mut sha256 = Sha256::new();
    sha256.update(msg);
    sha256.finish()
}

impl HardwareIdentity {
    fn sign_hash(&self, hash: &Sha256Hash) -> Result<Vec<u8>, String> {
        let private_key_handle =
            get_private_key_handle(&self.ctx, self.session_handle, &self.key_id)
                .map_err(|e| format!("Failed to get private key handle: {}", e))?;

        let mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.ctx
            .sign_init(self.session_handle, &mechanism, private_key_handle)
            .map_err(|e| format!("Failed to initialize signature: {}", e))?;
        self
            .ctx
            .sign(self.session_handle, hash)
            .map_err(|e| format!("Failed to generate signature: {}", e))
    }
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

#[cfg(test)]
mod tests {
    use crate::hsm::str_to_key_id;
    use crate::HardwareIdentity;

    #[test]
    fn it_works() {
        let hid = HardwareIdentity::new(
            "/usr/local/lib/opensc-pkcs11.so".to_string(),
            0,
            "abcdef",
            "837235",
        )
        .unwrap();
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn key_id_conversion_successful() {
        let key_id_v = str_to_key_id("a53f61e3").unwrap();
        assert_eq!(key_id_v, vec![0xa5, 0x3f, 0x61, 0xe3]);
    }
}
