use crate::{export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use k256::{
    ecdsa::{self, signature::Signer, SigningKey, VerifyingKey},
    elliptic_curve::{sec1::ToEncodedPoint, AlgorithmParameters},
    pkcs8::{PublicKeyDocument, SubjectPublicKeyInfo},
    Secp256k1, SecretKey,
};
use std::convert::TryInto;
#[cfg(feature = "pem")]
use std::{fs::File, io, path::Path};

/// A cryptographic identity based on the Secp256k1 elliptic curve.
///
/// The caller will be represented via [`Principal::self_authenticating`], which contains the SHA-224 hash of the public key.
#[derive(Clone, Debug)]
pub struct Secp256k1Identity {
    private_key: SigningKey,
    _public_key: VerifyingKey,
    der_encoded_public_key: PublicKeyDocument,
}

impl Secp256k1Identity {
    /// Creates an identity from a PEM file. Shorthand for calling `from_pem` with `std::fs::read`.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(File::open(file_path)?)
    }

    /// Creates an identity from a PEM certificate.
    #[cfg(feature = "pem")]
    pub fn from_pem<R: io::Read>(pem_reader: R) -> Result<Self, PemError> {
        use sec1::{pem::PemLabel, EcPrivateKeyDocument};

        const EC_PARAMETERS: &str = "EC PARAMETERS";
        const SECP256K1: &[u8] = b"\x06\x05\x2b\x81\x04\x00\x0a";

        let contents = pem_reader.bytes().collect::<Result<Vec<u8>, io::Error>>()?;

        for pem in pem::parse_many(contents)? {
            if pem.tag == EC_PARAMETERS && pem.contents != SECP256K1 {
                return Err(PemError::ErrorStack(
                    k256::pkcs8::Error::ParametersMalformed,
                ));
            }

            if pem.tag != EcPrivateKeyDocument::TYPE_LABEL {
                continue;
            }
            let private_key =
                SecretKey::from_sec1_der(&pem.contents).map_err(|_| pkcs8::Error::KeyMalformed)?;
            return Ok(Self::from_private_key(private_key));
        }
        Err(pem::PemError::MissingData.into())
    }

    /// Creates an identity from a private key.
    pub fn from_private_key(private_key: SecretKey) -> Self {
        let public_key = private_key.public_key();
        let public_key_bytes = public_key.to_encoded_point(false);
        let der_encoded_public_key = SubjectPublicKeyInfo {
            algorithm: Secp256k1::algorithm_identifier(),
            subject_public_key: public_key_bytes.as_ref(),
        }
        .try_into()
        .expect("Cannot DER encode secp256k1 public key.");
        Self {
            private_key: private_key.into(),
            _public_key: public_key.into(),
            der_encoded_public_key,
        }
    }
}

impl Identity for Secp256k1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(
            self.der_encoded_public_key.as_ref(),
        ))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let ecdsa_sig: ecdsa::Signature = self
            .private_key
            .try_sign(msg)
            .map_err(|err| format!("Cannot create secp256k1 signature: {}", err))?;
        let r = ecdsa_sig.r().as_ref().to_bytes();
        let s = ecdsa_sig.s().as_ref().to_bytes();
        let mut bytes = [0; 64];
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[(64 - s.len())..64].clone_from_slice(&s);
        let signature = Some(bytes.to_vec());
        let public_key = Some(self.der_encoded_public_key.as_ref().to_vec());
        Ok(Signature {
            public_key,
            signature,
        })
    }
}

#[cfg(feature = "pem")]
#[cfg(test)]
mod test {
    use super::*;
    use k256::{
        ecdsa::{signature::Verifier, Signature},
        elliptic_curve::PrimeField,
        FieldBytes, Scalar,
    };

    // WRONG_CURVE_IDENTITY_FILE is generated from the following command:
    // > openssl ecparam -name secp160r2 -genkey
    // it uses hte secp160r2 curve instead of secp256k1 and should
    // therefore be rejected by Secp256k1Identity when loading an identity
    const WRONG_CURVE_IDENTITY_FILE: &str = "-----BEGIN EC PARAMETERS-----
BgUrgQQAHg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MFACAQEEFI9cF6zXxMKhtjn1gBD7AHPbzehfoAcGBSuBBAAeoSwDKgAEh5NXszgR
oGSXVWaGxcQhQWlFG4pbnOG+93xXzfRD7eKWOdmun2bKxQ==
-----END EC PRIVATE KEY-----
";

    // WRONG_CURVE_IDENTITY_FILE_NO_PARAMS is generated from the following command:
    // > openssl ecparam -name secp160r2 -genkey -noout
    // it uses hte secp160r2 curve instead of secp256k1 and should
    // therefore be rejected by Secp256k1Identity when loading an identity
    const WRONG_CURVE_IDENTITY_FILE_NO_PARAMS: &str = "-----BEGIN EC PRIVATE KEY-----
MFACAQEEFI9cF6zXxMKhtjn1gBD7AHPbzehfoAcGBSuBBAAeoSwDKgAEh5NXszgR
oGSXVWaGxcQhQWlFG4pbnOG+93xXzfRD7eKWOdmun2bKxQ==
-----END EC PRIVATE KEY-----
";

    // IDENTITY_FILE was generated from the the following commands:
    // > openssl ecparam -name secp256k1 -genkey -noout -out identity.pem
    // > cat identity.pem
    const IDENTITY_FILE: &str = "-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIAgy7nZEcVHkQ4Z1Kdqby8SwyAiyKDQmtbEHTIM+WNeBoAcGBSuBBAAK
oUQDQgAEgO87rJ1ozzdMvJyZQ+GABDqUxGLvgnAnTlcInV3NuhuPv4O3VGzMGzeB
N3d26cRxD99TPtm8uo2OuzKhSiq6EQ==
-----END EC PRIVATE KEY-----
";

    // DER_ENCODED_PUBLIC_KEY was generated from the the following commands:
    // > openssl ec -in identity.pem -pubout -outform DER -out public.der
    // > hexdump -ve '1/1 "%.2x"' public.der
    const DER_ENCODED_PUBLIC_KEY: &str = "3056301006072a8648ce3d020106052b8104000a0342000480ef3bac9d68cf374cbc9c9943e180043a94c462ef8270274e57089d5dcdba1b8fbf83b7546ccc1b3781377776e9c4710fdf533ed9bcba8d8ebb32a14a2aba11";

    #[test]
    #[should_panic(expected = "ParametersMalformed")]
    fn test_secp256k1_reject_wrong_curve() {
        Secp256k1Identity::from_pem(WRONG_CURVE_IDENTITY_FILE.as_bytes()).unwrap();
    }

    #[test]
    #[should_panic(expected = "KeyMalformed")]
    fn test_secp256k1_reject_wrong_curve_no_id() {
        Secp256k1Identity::from_pem(WRONG_CURVE_IDENTITY_FILE_NO_PARAMS.as_bytes()).unwrap();
    }

    #[test]
    fn test_secp256k1_public_key() {
        // Create a secp256k1 identity from a PEM file.
        let identity = Secp256k1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create secp256k1 identity from PEM file.");

        // Assert the DER-encoded secp256k1 public key matches what we would expect.
        assert!(DER_ENCODED_PUBLIC_KEY == hex::encode(identity.der_encoded_public_key));
    }

    #[test]
    fn test_secp256k1_signature() {
        // Create a secp256k1 identity from a PEM file.
        let identity = Secp256k1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create secp256k1 identity from PEM file.");

        // Create a secp256k1 signature on the message "Hello World".
        let message = b"Hello World";
        let signature = identity
            .sign(message)
            .expect("Cannot create secp256k1 signature.")
            .signature
            .expect("Cannot find secp256k1 signature bytes.");

        // Import the secp256k1 signature into OpenSSL.
        let r: Scalar = Option::from(Scalar::from_repr(*FieldBytes::from_slice(
            &signature[0..32],
        )))
        .expect("Cannot extract r component from secp256k1 signature bytes.");
        let s: Scalar = Option::from(Scalar::from_repr(*FieldBytes::from_slice(&signature[32..])))
            .expect("Cannot extract s component from secp256k1 signature bytes.");
        let ecdsa_sig = Signature::from_scalars(r, s)
            .expect("Cannot create secp256k1 signature from r and s components.");

        // Assert the secp256k1 signature is valid.
        identity
            ._public_key
            .verify(message, &ecdsa_sig)
            .expect("Cannot verify secp256k1 signature.");
    }
}
