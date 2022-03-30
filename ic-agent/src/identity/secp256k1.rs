use crate::{export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use openssl::{
    bn::BigNumContext,
    ec::{EcKey, PointConversionForm},
    ecdsa::EcdsaSig,
    error::ErrorStack,
    nid::Nid,
    pkey::{Private, Public},
    sha::sha256,
};
use simple_asn1::{
    oid, to_der, ASN1Block,
    ASN1Block::{BitString, ObjectIdentifier, Sequence},
};

/// A cryptographic identity based on the Secp256k1 elliptic curve.
///
/// The caller will be represented via [`Principal::self_authenticating`], which contains the SHA-224 hash of the public key.
#[derive(Clone, Debug)]
pub struct Secp256k1Identity {
    private_key: EcKey<Private>,
    _public_key: EcKey<Public>,
    der_encoded_public_key: Vec<u8>,
}

impl Secp256k1Identity {
    /// Creates an identity from a PEM file. Shorthand for calling `from_pem` with `std::fs::read`.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    /// Creates an identity from a PEM certificate.
    #[cfg(feature = "pem")]
    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        let contents = pem_reader
            .bytes()
            .collect::<Result<Vec<u8>, std::io::Error>>()?;
        let private_key = EcKey::private_key_from_pem(&contents)?;
        Ok(Self::from_private_key(private_key))
    }

    /// Creates an identity from a private key.
    pub fn from_private_key(private_key: EcKey<Private>) -> Self {
        let group = private_key.group();
        if group.curve_name() != Some(Nid::SECP256K1) {
            panic!("Wrong curve detected when trying to load secp256k1 identity.")
        }
        let public_key = EcKey::from_public_key(group, private_key.public_key())
            .expect("Cannot derive secp256k1 public key.");
        let asn1_block = public_key_to_asn1_block(public_key.clone())
            .expect("Cannot ASN1 encode secp256k1 public key.");
        let der_encoded_public_key =
            to_der(&asn1_block).expect("Cannot DER encode secp256k1 public key.");
        Self {
            private_key,
            _public_key: public_key,
            der_encoded_public_key,
        }
    }
}

impl Identity for Secp256k1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.der_encoded_public_key))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let digest = sha256(msg);
        let ecdsa_sig = EcdsaSig::sign(&digest, &self.private_key.clone())
            .map_err(|err| format!("Cannot create secp256k1 signature: {}", err))?;
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        let mut bytes = [0; 64];
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[(64 - s.len())..64].clone_from_slice(&s);
        let signature = Some(bytes.to_vec());
        let public_key = Some(self.der_encoded_public_key.clone());
        Ok(Signature {
            public_key,
            signature,
        })
    }
}

fn public_key_to_asn1_block(public_key: EcKey<Public>) -> Result<ASN1Block, ErrorStack> {
    let mut context = BigNumContext::new()?;
    let bytes = public_key.public_key().to_bytes(
        public_key.group(),
        PointConversionForm::UNCOMPRESSED,
        &mut context,
    )?;
    let ec_public_key_id = ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1));
    let secp256k1_id = ObjectIdentifier(0, oid!(1, 3, 132, 0, 10));
    let metadata = Sequence(0, vec![ec_public_key_id, secp256k1_id]);
    let data = BitString(0, bytes.len() * 8, bytes);
    Ok(Sequence(0, vec![metadata, data]))
}

#[cfg(test)]
mod test {
    use super::*;

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

    #[test]
    #[should_panic(expected = "Wrong curve detected when trying to load secp256k1 identity.")]
    fn test_secp256k1_reject_wrong_curve() {
        let private_key =
            EcKey::private_key_from_pem(WRONG_CURVE_IDENTITY_FILE.as_bytes()).unwrap();

        let _ = Secp256k1Identity::from_private_key(private_key);
    }
}

#[cfg(feature = "pem")]
#[cfg(test)]
mod test_pem {
    use super::*;
    use openssl::bn::BigNum;

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
        let r = BigNum::from_slice(&signature[0..32])
            .expect("Cannot extract r component from secp256k1 signature bytes.");
        let s = BigNum::from_slice(&signature[32..])
            .expect("Cannot extract s component from secp256k1 signature bytes.");
        let ecdsa_sig = EcdsaSig::from_private_components(r, s)
            .expect("Cannot create secp256k1 signature from r and s components.");

        // Assert the secp256k1 signature is valid.
        let digest = sha256(message);
        let public_key = identity._public_key;
        let success = ecdsa_sig
            .verify(&digest, &public_key)
            .expect("Cannot verify secp256k1 signature.");
        assert!(success);
    }
}
