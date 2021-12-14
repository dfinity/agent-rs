use ic_agent::{ic_types::Principal, Identity, Signature};

use openssl::sha::Sha256;
use pkcs11::{
    types::{
        CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_LOGIN_REQUIRED,
        CKF_SERIAL_SESSION, CKK_ECDSA, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKU_USER,
        CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_KEY_TYPE, CK_MECHANISM, CK_OBJECT_CLASS,
        CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID,
    },
    Ctx,
};
use simple_asn1::{
    from_der, oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, OctetString, Sequence},
    ASN1DecodeErr, ASN1EncodeErr,
};
use std::{path::Path, ptr};
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

    // ASN1DecodeError does not implement the Error trait and so we cannot use #[from]
    #[error("ASN decode error {0}")]
    ASN1Decode(ASN1DecodeErr),

    #[error(transparent)]
    ASN1Encode(#[from] ASN1EncodeErr),

    #[error(transparent)]
    KeyIdDecode(#[from] hex::FromHexError),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Unexpected key type {0}")]
    UnexpectedKeyType(CK_KEY_TYPE),

    #[error("Expected EcPoint to be an OctetString")]
    ExpectedEcPointOctetString,

    #[error("EcPoint is empty")]
    EcPointEmpty,

    #[error("Attribute with type={0} not found")]
    AttributeNotFound(CK_ATTRIBUTE_TYPE),

    #[error("Invalid EcParams.  Expected prime256v1 {:02x?}, actual is {:02x?}", .expected, .actual)]
    InvalidEcParams { expected: Vec<u8>, actual: Vec<u8> },

    #[error("User PIN is required: {0}")]
    UserPinRequired(String),

    #[error("No such slot index ({0}")]
    NoSuchSlotIndex(usize),
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
    /// The filename will be something like /usr/local/lib/opensc-pkcs11.s
    /// The key_id must refer to a ECDSA key with parameters prime256v1 (secp256r1)
    /// The key must already have been created.  You can create one with pkcs11-tool:
    /// $ pkcs11-tool -k --slot $SLOT -d $KEY_ID --key-type EC:prime256v1 --pin $PIN
    pub fn new<P, PinFn>(
        pkcs11_lib_path: P,
        slot_index: usize,
        key_id: &str,
        pin_fn: PinFn,
    ) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
        PinFn: FnOnce() -> Result<String, String>,
    {
        let ctx = Ctx::new_and_initialize(pkcs11_lib_path)?;
        let slot_id = get_slot_id(&ctx, slot_index)?;
        let session_handle = open_session(&ctx, slot_id)?;
        let logged_in = login_if_required(&ctx, session_handle, pin_fn, slot_id)?;
        let key_id = str_to_key_id(key_id)?;
        let public_key = get_der_encoded_public_key(&ctx, session_handle, &key_id)?;

        Ok(HardwareIdentity {
            key_id,
            ctx,
            session_handle,
            logged_in,
            public_key,
        })
    }
}

impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let hash = hash_message(msg);
        let signature = self.sign_hash(&hash)?;

        Ok(Signature {
            public_key: Some(self.public_key.clone()),
            signature: Some(signature),
        })
    }
}

fn get_slot_id(ctx: &Ctx, slot_index: usize) -> Result<CK_SLOT_ID, HardwareIdentityError> {
    ctx.get_slot_list(true)?
        .get(slot_index)
        .ok_or(HardwareIdentityError::NoSuchSlotIndex(slot_index))
        .map(|x| *x)
}

// We open a session for the duration of the lifetime of the HardwareIdentity.
fn open_session(
    ctx: &Ctx,
    slot_id: CK_SLOT_ID,
) -> Result<CK_SESSION_HANDLE, HardwareIdentityError> {
    let flags = CKF_SERIAL_SESSION;
    let application = None;
    let notify = None;
    let session_handle = ctx.open_session(slot_id, flags, application, notify)?;
    Ok(session_handle)
}

// We might need to log in.  This requires the PIN.
fn login_if_required<PinFn>(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    pin_fn: PinFn,
    slot_id: CK_SLOT_ID,
) -> Result<bool, HardwareIdentityError>
where
    PinFn: FnOnce() -> Result<String, String>,
{
    let token_info = ctx.get_token_info(slot_id)?;
    let login_required = token_info.flags & CKF_LOGIN_REQUIRED != 0;

    if login_required {
        let pin = pin_fn().map_err(HardwareIdentityError::UserPinRequired)?;
        ctx.login(session_handle, CKU_USER, Some(&pin))?;
    }
    Ok(login_required)
}

// Return the DER-encoded public key in the expected format.
// We also validate that it's an ECDSA key on the correct curve.
fn get_der_encoded_public_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<DerPublicKeyVec, HardwareIdentityError> {
    let object_handle = get_public_key_handle(ctx, session_handle, key_id)?;

    validate_key_type(ctx, session_handle, object_handle)?;
    validate_ec_params(ctx, session_handle, object_handle)?;

    let ec_point = get_ec_point(ctx, session_handle, object_handle)?;

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

// Ensure that the key type is ECDSA.
fn validate_key_type(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    // The call to ctx.get_attribute_value() will mutate kt!
    // with_ck_ulong` stores &kt as a mutable pointer by casting it to CK_VOID_PTR, which is:
    //      pub type CK_VOID_PTR = *mut CK_VOID;
    // `let mut kt...` here emits a warning, unfortunately.
    let kt: CK_KEY_TYPE = 0;

    let mut attribute_types = vec![CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&kt)];
    ctx.get_attribute_value(session_handle, object_handle, &mut attribute_types)?;
    if kt != CKK_ECDSA {
        Err(HardwareIdentityError::UnexpectedKeyType(kt))
    } else {
        Ok(())
    }
}

// We just want to make sure that we are using the expected EC curve prime256v1 (secp256r1),
// since the HSMs also support things like secp384r1 and secp512r1.
fn validate_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    let ec_params = get_ec_params(ctx, session_handle, object_handle)?;
    if ec_params != EXPECTED_EC_PARAMS {
        Err(HardwareIdentityError::InvalidEcParams {
            expected: EXPECTED_EC_PARAMS.to_vec(),
            actual: ec_params,
        })
    } else {
        Ok(())
    }
}

// Obtain the EcPoint, which is an (x,y) coordinate.  Each coordinate is 32 bytes.
// These are preceded by an 04 byte meaning "uncompressed point."
// The returned vector will therefore have len=65.
fn get_ec_point(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let der_encoded_ec_point =
        get_variable_length_attribute(ctx, session_handle, object_handle, CKA_EC_POINT)?;

    let blocks =
        from_der(der_encoded_ec_point.as_slice()).map_err(HardwareIdentityError::ASN1Decode)?;
    let block = blocks.get(0).ok_or(HardwareIdentityError::EcPointEmpty)?;
    if let OctetString(_size, data) = block {
        Ok(data.clone())
    } else {
        Err(HardwareIdentityError::ExpectedEcPointOctetString)
    }
}

// In order to read a variable-length attribute, we need to first read its length.
fn get_attribute_length(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<usize, HardwareIdentityError> {
    let mut attributes = vec![CK_ATTRIBUTE::new(attribute_type)];
    ctx.get_attribute_value(session_handle, object_handle, &mut attributes)?;

    let first = attributes
        .get(0)
        .ok_or(HardwareIdentityError::AttributeNotFound(attribute_type))?;
    Ok(first.ulValueLen as usize)
}

// Get a variable-length attribute, by first reading its length and then the value.
fn get_variable_length_attribute(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let length = get_attribute_length(ctx, session_handle, object_handle, attribute_type)?;
    let value = vec![0; length];

    let mut attrs = vec![CK_ATTRIBUTE::new(attribute_type).with_bytes(value.as_slice())];
    ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    Ok(value)
}

fn get_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    get_variable_length_attribute(ctx, session_handle, object_handle, CKA_EC_PARAMS)
}

fn get_public_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_for_key(ctx, session_handle, key_id, CKO_PUBLIC_KEY)
}

fn get_private_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_for_key(ctx, session_handle, key_id, CKO_PRIVATE_KEY)
}

// Find a public or private key.
fn get_object_handle_for_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
    object_class: CK_OBJECT_CLASS,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    let attributes = [
        CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id),
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_class),
    ];
    ctx.find_objects_init(session_handle, &attributes)?;
    let object_handles = ctx.find_objects(session_handle, 1)?;
    let object_handle = *object_handles
        .get(0)
        .ok_or(HardwareIdentityError::KeyNotFound)?;
    ctx.find_objects_final(session_handle)?;
    Ok(object_handle)
}

// A key id is a sequence of pairs of hex digits, case-insensitive.
fn str_to_key_id(s: &str) -> Result<KeyIdVec, HardwareIdentityError> {
    let bytes = hex::decode(s)?;
    Ok(bytes)
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
        self.ctx
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

    #[test]
    fn key_id_conversion() {
        let key_id_v = str_to_key_id("a53f61e3").unwrap();
        assert_eq!(key_id_v, vec![0xa5, 0x3f, 0x61, 0xe3]);
    }
}
