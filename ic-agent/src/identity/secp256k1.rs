use crate::{export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use k256::{
    ecdsa::{self, signature::Signer, SigningKey, VerifyingKey},
    elliptic_curve::{sec1::ToEncodedPoint, AlgorithmParameters},
    pkcs8::{self, PublicKeyDocument, SubjectPublicKeyInfo},
    Secp256k1, SecretKey,
};
#[cfg(feature = "pem")]
use std::{convert::TryInto, fs::File, io, path::Path};

#[derive(Clone, Debug)]
pub struct Secp256k1Identity {
    private_key: SigningKey,
    public_key: VerifyingKey,
    der_encoded_public_key: PublicKeyDocument,
}

impl Secp256k1Identity {
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(File::open(file_path)?)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem<R: io::Read>(pem_reader: R) -> Result<Self, PemError> {
        use sec1::{pem::PemLabel, EcPrivateKeyDocument};

        let contents = pem_reader.bytes().collect::<Result<Vec<u8>, io::Error>>()?;

        for pem in pem::parse_many(contents)? {
            if pem.tag != EcPrivateKeyDocument::TYPE_LABEL {
                continue;
            }
            let private_key =
                SecretKey::from_sec1_der(&pem.contents).map_err(|_| pkcs8::Error::KeyMalformed)?;
            return Ok(Self::from_private_key(private_key));
        }
        return Err(pem::PemError::MissingData.into());
    }

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
            public_key: public_key.into(),
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
            .map_err(|err| format!("Cannot create secp256k1 signature: {}", err.to_string(),))?;
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
            .public_key
            .verify(message, &ecdsa_sig)
            .expect("Cannot verify secp256k1 signature.");
    }
}
