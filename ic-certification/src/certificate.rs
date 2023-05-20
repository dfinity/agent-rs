use crate::hash_tree::HashTree;

/// A `Certificate` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate>
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "Storage: serde_bytes::Serialize"))
)]
pub struct Certificate<Storage: AsRef<[u8]>> {
    /// The hash tree.
    pub tree: HashTree<Storage>,

    /// The signature of the root hash in `tree`.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub signature: Storage,

    /// A delegation from the root key to the key used to sign `signature`, if one exists.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub delegation: Option<Delegation<Storage>>,
}

/// A `Delegation` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification-delegation>
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(serialize = "Storage: serde_bytes::Serialize"))
)]
pub struct Delegation<Storage: AsRef<[u8]>> {
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub subnet_id: Storage,

    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub certificate: Storage,
}

#[cfg(feature = "serde")]
mod serde_impl {
    use super::{Certificate, Delegation};
    use crate::{hash_tree::HashTreeNode, serde_impl::*};

    use std::{borrow::Cow, fmt, marker::PhantomData};

    use serde::{
        de::{self, MapAccess, SeqAccess, Visitor},
        Deserialize, Deserializer,
    };

    #[derive(Deserialize)]
    #[serde(field_identifier, rename_all = "snake_case")]
    enum CertificateField {
        Tree,
        Signature,
        Delegation,
    }
    struct CertificateVisitor<S>(PhantomData<S>);

    impl<'de, S: Storage> Visitor<'de> for CertificateVisitor<S>
    where
        Delegation<S::Value<'de>>: Deserialize<'de>,
        HashTreeNode<S::Value<'de>>: Deserialize<'de>,
    {
        type Value = Certificate<S::Value<'de>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("struct Delegation")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let tree = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let signature = S::convert(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?,
            );
            let delegation = seq.next_element()?;

            Ok(Certificate {
                tree,
                signature,
                delegation,
            })
        }

        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: MapAccess<'de>,
        {
            let mut tree = None;
            let mut signature = None;
            let mut delegation = None;
            while let Some(key) = map.next_key()? {
                match key {
                    CertificateField::Tree => {
                        if tree.is_some() {
                            return Err(de::Error::duplicate_field("tree"));
                        }
                        tree = Some(map.next_value()?);
                    }
                    CertificateField::Signature => {
                        if signature.is_some() {
                            return Err(de::Error::duplicate_field("signature"));
                        }
                        signature = Some(map.next_value()?);
                    }
                    CertificateField::Delegation => {
                        if delegation.is_some() {
                            return Err(de::Error::duplicate_field("signature"));
                        }
                        delegation = Some(map.next_value()?);
                    }
                }
            }
            let tree = tree.ok_or_else(|| de::Error::missing_field("tree"))?;
            let signature =
                S::convert(signature.ok_or_else(|| de::Error::missing_field("signature"))?);
            Ok(Certificate {
                tree,
                signature,
                delegation,
            })
        }
    }

    fn deserialize_certificate<'de, S: Storage, D>(
        deserializer: D,
    ) -> Result<Certificate<S::Value<'de>>, D::Error>
    where
        Delegation<S::Value<'de>>: Deserialize<'de>,
        HashTreeNode<S::Value<'de>>: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["tree", "signature", "delegation"];
        deserializer.deserialize_struct("Certificate", FIELDS, CertificateVisitor::<S>(PhantomData))
    }

    impl<'de> Deserialize<'de> for Certificate<Vec<u8>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_certificate::<VecStorage, _>(deserializer)
        }
    }

    impl<'de> Deserialize<'de> for Certificate<&'de [u8]> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_certificate::<SliceStorage, _>(deserializer)
        }
    }

    impl<'de> Deserialize<'de> for Certificate<Cow<'de, [u8]>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_certificate::<CowStorage, _>(deserializer)
        }
    }

    #[derive(Deserialize)]
    #[serde(field_identifier, rename_all = "snake_case")]
    enum DelegationField {
        SubnetId,
        Certificate,
    }
    struct DelegationVisitor<S>(PhantomData<S>);

    impl<'de, S: Storage> Visitor<'de> for DelegationVisitor<S> {
        type Value = Delegation<S::Value<'de>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("struct Delegation")
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: SeqAccess<'de>,
        {
            let subnet_id = S::convert(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?,
            );
            let certificate = S::convert(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?,
            );
            Ok(Delegation {
                subnet_id,
                certificate,
            })
        }

        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: MapAccess<'de>,
        {
            let mut subnet_id = None;
            let mut certificate = None;
            while let Some(key) = map.next_key()? {
                match key {
                    DelegationField::SubnetId => {
                        if subnet_id.is_some() {
                            return Err(de::Error::duplicate_field("subnet_id"));
                        }
                        subnet_id = Some(map.next_value()?);
                    }
                    DelegationField::Certificate => {
                        if certificate.is_some() {
                            return Err(de::Error::duplicate_field("certificate"));
                        }
                        certificate = Some(map.next_value()?);
                    }
                }
            }
            let subnet_id =
                S::convert(subnet_id.ok_or_else(|| de::Error::missing_field("subnet_id"))?);
            let certificate =
                S::convert(certificate.ok_or_else(|| de::Error::missing_field("certificate"))?);
            Ok(Delegation {
                subnet_id,
                certificate,
            })
        }
    }

    fn deserialize_delegation<'de, S: Storage, D>(
        deserializer: D,
    ) -> Result<Delegation<S::Value<'de>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["subnet_id", "certificate"];
        deserializer.deserialize_struct("Delegation", FIELDS, DelegationVisitor::<S>(PhantomData))
    }

    impl<'de> Deserialize<'de> for Delegation<Vec<u8>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_delegation::<VecStorage, _>(deserializer)
        }
    }

    impl<'de> Deserialize<'de> for Delegation<&'de [u8]> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_delegation::<SliceStorage, _>(deserializer)
        }
    }

    impl<'de> Deserialize<'de> for Delegation<Cow<'de, [u8]>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserialize_delegation::<CowStorage, _>(deserializer)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;
    use crate::hash_tree::{empty, fork, label, leaf};

    fn create_tree() -> HashTree<Vec<u8>> {
        fork(
            fork(
                label(
                    "a",
                    fork(
                        fork(label("x", leaf(*b"hello")), empty()),
                        label("y", leaf(*b"world")),
                    ),
                ),
                label("b", leaf(*b"good")),
            ),
            fork(label("c", empty()), label("d", leaf(*b"morning"))),
        )
    }

    #[test]
    fn serialize_to_cbor() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];

        let certificate = Certificate {
            tree,
            signature,
            delegation: None,
        };

        let cbor_bytes =
            serde_cbor::to_vec(&certificate).expect("Failed to encode certificate to cbor");
        let cbor_hex = hex::encode(cbor_bytes);

        assert_eq!(cbor_hex, "a264747265658301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67697369676e617475726546010203040506");
    }

    #[test]
    fn serialize_to_cbor_with_delegation() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];
        let delegation = Delegation {
            subnet_id: vec![7, 8, 9, 10, 11, 12],
            certificate: vec![13, 14, 15, 16, 17, 18],
        };

        let certificate = Certificate {
            tree,
            signature,
            delegation: Some(delegation),
        };

        let cbor_bytes =
            serde_cbor::to_vec(&certificate).expect("Failed to encode certificate to cbor");
        let cbor_hex = hex::encode(cbor_bytes);

        assert_eq!(cbor_hex, "a364747265658301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67697369676e6174757265460102030405066a64656c65676174696f6ea2697375626e65745f6964460708090a0b0c6b6365727469666963617465460d0e0f101112");
    }
}
