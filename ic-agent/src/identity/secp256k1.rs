use crate::export::Principal;
use crate::identity::error::PemError;
use crate::{Identity, Signature};

use num_bigint::BigUint;
use openssl::bn::BigNumContext;
use openssl::ec::{EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;
use simple_asn1::ASN1Block;
use simple_asn1::ASN1Block::{BitString, Integer, ObjectIdentifier, Sequence};
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
        let signature = ecdsa_sig.to_der().map(Some).map_err(|err| {
            format!("Cannot DER ecnode secp256k1 signature: {}", err.to_string(),)
        })?;
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
    let asn1_metadata = Sequence(
        0,
        vec![
            ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1)),
            ObjectIdentifier(0, oid!(1, 3, 132, 0, 10)),
        ],
    );
    let asn1_public_key = BitString(0, bytes.len() * 8, bytes);
    Ok(Sequence(0, vec![asn1_metadata, asn1_public_key]))
}

mod test {
    use crate::identity::secp256k1::Secp256k1Identity;

    fn create_identity() -> Secp256k1Identity {
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

        Secp256k1Identity::from_pem(IDENTITY_FILE.as_bytes())
            .expect("Cannot create secp256k1 identity from PEM file.")
    }

    #[test]
    fn test_from_pem() {
        // DER_ENCODED_PUBLIC_KEY was generated from the the following commands:
        // > openssl ec -in identity.pem -pubout -outform DER -out public.der
        // > hexdump -ve '1/1 "%.2x"' public.der
        const DER_ENCODED_PUBLIC_KEY: &str = "3056301006072a8648ce3d020106052b8104000a0342000480ef3bac9d68cf374cbc9c9943e180043a94c462ef8270274e57089d5dcdba1b8fbf83b7546ccc1b3781377776e9c4710fdf533ed9bcba8d8ebb32a14a2aba11";

        let identity = create_identity();
        assert!(DER_ENCODED_PUBLIC_KEY == hex::encode(identity.der_encoded_public_key));
    }
}
