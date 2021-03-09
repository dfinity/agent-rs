use crate::export::Principal;
use crate::{Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use num_bigint::BigUint;
use openssl::bn::BigNumContext;
use openssl::ec::{EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::pkey::{Private, Public};
use simple_asn1::ASN1Block;
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, Sequence};
use simple_asn1::{oid, to_der, OID};

#[derive(Clone, Debug)]
pub struct Secp256k1Identity {
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    der_encoded_public_key: Vec<u8>,
}

impl Secp256k1Identity {
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        let contents = pem_reader
            .bytes()
            .collect::<Result<Vec<u8>, std::io::Error>>()?;
        let private_key = EcKey::private_key_from_pem(&contents)?;
        Ok(Self::from_private_key(private_key))
    }

    pub fn from_private_key(private_key: EcKey<Private>) -> Self {
        let group = private_key.group();
        let public_key = EcKey::from_public_key(group, private_key.public_key())
            .expect("Cannot derive secp256k1 public key.");
        let asn1_block = public_key_to_asn1_block(public_key.clone())
            .expect("Cannot ASN1 encode secp256k1 public key.");
        let der_encoded_public_key =
            to_der(&asn1_block).expect("Cannot DER encode secp256k1 public key.");
        Self {
            private_key,
            public_key,
            der_encoded_public_key,
        }
    }
}

impl Identity for Secp256k1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.der_encoded_public_key))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let ecdsa_sig = EcdsaSig::sign(msg, &self.private_key.clone())
            .map_err(|err| format!("Cannot create secp256k1 signature: {}", err.to_string(),))?;
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        let mut bytes = [0; 64];
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[(64 - s.len())..64].clone_from_slice(&s);
        let signature = Some(bytes.to_vec());
        let public_key = Some(self.der_encoded_public_key.clone());
        Ok(Signature {
            signature,
            public_key,
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

#[cfg(feature = "pem")]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_pem() {
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

        // Create a secp256k1 identity from a PEM file.
        let identity = Secp256k1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create secp256k1 identity from PEM file.");

        // Assert the DER-encoded public key matches what we would expect.
        assert!(DER_ENCODED_PUBLIC_KEY == hex::encode(identity.der_encoded_public_key));
    }
}
