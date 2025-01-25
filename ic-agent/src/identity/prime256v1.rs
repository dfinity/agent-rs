use crate::{agent::EnvelopeContent, export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use async_trait::async_trait;
use p256::{
    ecdsa::{self, signature::Signer, SigningKey, VerifyingKey},
    pkcs8::{Document, EncodePublicKey},
    SecretKey,
};
#[cfg(feature = "pem")]
use std::{fs::File, io, path::Path};

use super::Delegation;

/// A cryptographic identity based on the Prime256v1 elliptic curve.
///
/// The caller will be represented via [`Principal::self_authenticating`], which contains the SHA-224 hash of the public key.
#[derive(Clone, Debug)]
pub struct Prime256v1Identity {
    private_key: SigningKey,
    _public_key: VerifyingKey,
    der_encoded_public_key: Document,
}

impl Prime256v1Identity {
    /// Creates an identity from a PEM file. Shorthand for calling `from_pem` with `std::fs::read`.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(File::open(file_path)?)
    }

    /// Creates an identity from a PEM certificate.
    #[cfg(feature = "pem")]
    pub fn from_pem<R: io::Read>(pem_reader: R) -> Result<Self, PemError> {
        use sec1::{pem::PemLabel, EcPrivateKey};

        const EC_PARAMETERS: &str = "EC PARAMETERS";
        const PRIME256V1: &[u8] = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

        let contents = pem_reader.bytes().collect::<Result<Vec<u8>, io::Error>>()?;

        for pem in pem::parse_many(contents)? {
            if pem.tag() == EC_PARAMETERS && pem.contents() != PRIME256V1 {
                return Err(PemError::UnsupportedKeyCurve(
                    "prime256v1".to_string(),
                    pem.contents().to_vec(),
                ));
            }

            if pem.tag() != EcPrivateKey::PEM_LABEL {
                continue;
            }
            let private_key =
                SecretKey::from_sec1_der(pem.contents()).map_err(|_| pkcs8::Error::KeyMalformed)?;
            return Ok(Self::from_private_key(private_key));
        }
        Err(pem::PemError::MissingData.into())
    }

    /// Creates an identity from a private key.
    pub fn from_private_key(private_key: SecretKey) -> Self {
        let public_key = private_key.public_key();
        let der_encoded_public_key = public_key
            .to_public_key_der()
            .expect("Cannot DER encode prime256v1 public key.");
        Self {
            private_key: private_key.into(),
            _public_key: public_key.into(),
            der_encoded_public_key,
        }
    }
}
#[async_trait]
impl Identity for Prime256v1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(
            self.der_encoded_public_key.as_ref(),
        ))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der_encoded_public_key.as_ref().to_vec())
    }

  async  fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let ecdsa_sig: ecdsa::Signature = self
            .private_key
            .try_sign(content)
            .map_err(|err| format!("Cannot create prime256v1 signature: {err}"))?;
        let r = ecdsa_sig.r().as_ref().to_bytes();
        let s = ecdsa_sig.s().as_ref().to_bytes();
        let mut bytes = [0u8; 64];
        if r.len() > 32 || s.len() > 32 {
            return Err("Cannot create prime256v1 signature: malformed signature.".to_string());
        }
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[32 + (32 - s.len())..].clone_from_slice(&s);
        let signature = Some(bytes.to_vec());
        let public_key = self.public_key();
        Ok(Signature {
            public_key,
            signature,
            delegations: None,
        })
    }
}

#[cfg(feature = "pem")]
#[cfg(test)]
mod test {
    use super::*;
    use candid::Encode;
    use p256::{
        ecdsa::{signature::Verifier, Signature},
        elliptic_curve::PrimeField,
        FieldBytes, Scalar,
    };

    // WRONG_CURVE_IDENTITY_FILE is generated from the following command:
    // > openssl ecparam -name secp160r2 -genkey
    // it uses the secp160r2 curve instead of prime256v1 and should
    // therefore be rejected by Prime256v1Identity when loading an identity
    const WRONG_CURVE_IDENTITY_FILE: &str = "\
-----BEGIN EC PARAMETERS-----
BgUrgQQAHg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MFACAQEEFI9cF6zXxMKhtjn1gBD7AHPbzehfoAcGBSuBBAAeoSwDKgAEh5NXszgR
oGSXVWaGxcQhQWlFG4pbnOG+93xXzfRD7eKWOdmun2bKxQ==
-----END EC PRIVATE KEY-----
";

    // WRONG_CURVE_IDENTITY_FILE_NO_PARAMS is generated from the following command:
    // > openssl ecparam -name secp160r2 -genkey -noout
    // it uses the secp160r2 curve instead of prime256v1 and should
    // therefore be rejected by Prime256v1Identity when loading an identity
    const WRONG_CURVE_IDENTITY_FILE_NO_PARAMS: &str = "\
-----BEGIN EC PRIVATE KEY-----
MFACAQEEFI9cF6zXxMKhtjn1gBD7AHPbzehfoAcGBSuBBAAeoSwDKgAEh5NXszgR
oGSXVWaGxcQhQWlFG4pbnOG+93xXzfRD7eKWOdmun2bKxQ==
-----END EC PRIVATE KEY-----
";

    // IDENTITY_FILE was generated from the the following commands:
    // > openssl ecparam -name prime256v1 -genkey -noout -out identity.pem
    // > cat identity.pem
    const IDENTITY_FILE: &str = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL1ybmbwx+uKYsscOZcv71MmKhrNqfPP0ke1unET5AY4oAoGCCqGSM49
AwEHoUQDQgAEUbbZV4NerZTPWfbQ749/GNLu8TaH8BUS/I7/+ipsu+MPywfnBFIZ
Sks4xGbA/ZbazsrMl4v446U5UIVxCGGaKw==
-----END EC PRIVATE KEY-----
";

    // DER_ENCODED_PUBLIC_KEY was generated from the the following commands:
    // > openssl ec -in identity.pem -pubout -outform DER -out public.der
    // > hexdump -ve '1/1 "%.2x"' public.der
    const DER_ENCODED_PUBLIC_KEY: &str = "3059301306072a8648ce3d020106082a8648ce3d0301070342000451b6d957835ead94cf59f6d0ef8f7f18d2eef13687f01512fc8efffa2a6cbbe30fcb07e70452194a4b38c466c0fd96dacecacc978bf8e3a53950857108619a2b";

    #[test]
    #[should_panic(expected = "UnsupportedKeyCurve")]
    fn test_prime256v1_reject_wrong_curve() {
        Prime256v1Identity::from_pem(WRONG_CURVE_IDENTITY_FILE.as_bytes()).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyMalformed")]
    fn test_prime256v1_reject_wrong_curve_no_id() {
        Prime256v1Identity::from_pem(WRONG_CURVE_IDENTITY_FILE_NO_PARAMS.as_bytes()).unwrap();
    }

    #[test]
    fn test_prime256v1_public_key() {
        // Create a prime256v1 identity from a PEM file.
        let identity = Prime256v1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create prime256v1 identity from PEM file.");

        // Assert the DER-encoded prime256v1 public key matches what we would expect.
        assert!(DER_ENCODED_PUBLIC_KEY == hex::encode(identity.der_encoded_public_key));
    }

    #[tokio::test]
   async fn test_prime256v1_signature() {
        // Create a prime256v1 identity from a PEM file.
        let identity = Prime256v1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create prime256v1 identity from PEM file.");

        // Create a prime256v1 signature for a hello-world canister.
        let message = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 0,
            sender: identity.sender().unwrap(),
            canister_id: "bkyz2-fmaaa-aaaaa-qaaaq-cai".parse().unwrap(),
            method_name: "greet".to_string(),
            arg: Encode!(&"world").unwrap(),
        };
        let signature = identity
            .sign(&message).await
            .expect("Cannot create prime256v1 signature.")
            .signature
            .expect("Cannot find prime256v1 signature bytes.");

        // Import the prime256v1 signature.
        let r: Scalar = Option::from(Scalar::from_repr(*FieldBytes::from_slice(
            &signature[0..32],
        )))
        .expect("Cannot extract r component from prime256v1 signature bytes.");
        let s: Scalar = Option::from(Scalar::from_repr(*FieldBytes::from_slice(&signature[32..])))
            .expect("Cannot extract s component from prime256v1 signature bytes.");
        let ecdsa_sig = Signature::from_scalars(r, s)
            .expect("Cannot create prime256v1 signature from r and s components.");

        // Assert the prime256v1 signature is valid.
        identity
            ._public_key
            .verify(&message.to_request_id().signable(), &ecdsa_sig)
            .expect("Cannot verify prime256v1 signature.");
    }
}
