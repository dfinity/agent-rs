use crate::export::Principal;
use crate::identity::Identity;
use crate::Signature;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha::sha256;

// NOTE: prime256v1 is a yet another name for secp256r1 (aka. NIST P-256),
// cf. https://tools.ietf.org/html/rfc5480
const CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

/// An ECDSA identity on curve P-256, using SHA-256 as hash function.
pub struct Secp256r1Identity {
    key: EcKey<Private>,
}

impl Secp256r1Identity {
    /// Creates a random secp256r1 identity.
    ///
    /// Note that no RNG needs to be provided here as we're relying on the
    /// internal RNG of Openssl.
    pub fn new_random() -> Result<Self, String> {
        let group = EcGroup::from_curve_name(CURVE_NAME)
            .map_err(|e| format!("Unable to create EC group: {}", e.to_string()))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|e| format!("Unable to generate EC key: {}", e.to_string()))?;
        Ok(Self { key: ec_key })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, String> {
        self.key
            .public_key_to_der()
            .map_err(|e| format!("Failed to DER-encode public key: {}", e.to_string()))
    }
}

impl Identity for Secp256r1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key_der()?))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let msg = sha256(msg).to_vec();
        let ecdsa_sig = EcdsaSig::sign(&msg, &self.key)
            .map_err(|e| format!("Unable to sign: {}", e.to_string()))?;
        Ok(Signature {
            signature: Some(ecdsa_sig_to_bytes(ecdsa_sig)?.to_vec()),
            public_key: Some(self.public_key_der()?),
        })
    }
}

fn ecdsa_sig_to_bytes(ecdsa_sig: EcdsaSig) -> Result<[u8; 64], String> {
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();
    if r.len() > 32 || s.len() > 32 {
        return Err(format!(
           "Signature too long. Expected r <= 32 bits && s <= 32 bits but found r = {} bits && s = {} bits",
           r.len(), s.len()));
    }

    let mut bytes = [0; 64];
    // Account for leading zeros.
    bytes[(32 - r.len())..32].clone_from_slice(&r);
    bytes[(64 - s.len())..64].clone_from_slice(&s);
    Ok(bytes)
}
