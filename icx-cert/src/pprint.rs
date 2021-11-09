use anyhow::{anyhow, Context, Result};
use chrono::TimeZone;
use ic_agent::ic_types::{
    hash_tree::{Label, LookupResult},
    HashTree,
};
use reqwest::header;
use serde::{de::DeserializeOwned, Deserialize};
use sha2::Digest;

/// Structured contents of the IC-Certificate header.
struct StructuredCertHeader<'a> {
    certificate: &'a str,
    tree: &'a str,
}

/// A fully parsed replica certificate.
#[derive(Deserialize)]
struct ReplicaCertificate {
    tree: HashTree<'static>,
    signature: serde_bytes::ByteBuf,
}

/// Parses the value of IC-Certificate header.
fn parse_structured_cert_header(value: &str) -> Result<StructuredCertHeader<'_>> {
    fn extract_field<'a>(value: &'a str, field_name: &'a str, prefix: &'a str) -> Result<&'a str> {
        let start = value.find(prefix).ok_or_else(|| {
            anyhow!(
                "Certificate header doesn't have '{}' field: {}",
                field_name,
                value,
            )
        })? + prefix.len();
        let len = value[start..].find(':').ok_or_else(|| {
            anyhow!(
                "malformed '{}' field: no ending colon found: {}",
                prefix,
                value
            )
        })?;
        Ok(&value[start..(start + len)])
    }

    Ok(StructuredCertHeader {
        certificate: extract_field(value, "certificate", "certificate=:")?,
        tree: extract_field(value, "tree", "tree=:")?,
    })
}

/// Decodes base64-encoded CBOR value.
fn parse_base64_cbor<T: DeserializeOwned>(s: &str) -> Result<T> {
    let bytes = base64::decode(s).with_context(|| {
        format!(
            "failed to parse {}: invalid base64 {}",
            std::any::type_name::<T>(),
            s
        )
    })?;
    serde_cbor::from_slice(&bytes[..]).with_context(|| {
        format!(
            "failed to parse {}: malformed CBOR",
            std::any::type_name::<T>()
        )
    })
}

/// Downloads the asset with the specified URL and pretty-print certificate contents.
pub fn pprint(url: String, accept_encodings: Option<Vec<String>>) -> Result<()> {
    let response = {
        let client = reqwest::blocking::Client::builder();
        let client = if let Some(accept_encodings) = accept_encodings {
            let mut headers = header::HeaderMap::new();
            let accept_encodings: String = accept_encodings.join(", ");
            headers.insert(
                "Accept-Encoding",
                header::HeaderValue::from_str(&accept_encodings).unwrap(),
            );
            client.default_headers(headers)
        } else {
            client
        };
        client
            .build()?
            .get(url)
            .send()
            .with_context(|| "failed to fetch the document")?
    };

    let status = response.status().as_u16();
    let certificate_header = response
        .headers()
        .get("IC-Certificate")
        .ok_or_else(|| anyhow!("IC-Certificate header not found: {:?}", response.headers()))?
        .to_owned();
    let content_encoding = response
        .headers()
        .get("Content-Encoding")
        .map(|x| x.to_owned());
    let data = response
        .bytes()
        .with_context(|| "failed to get response body")?;
    let certificate_str = certificate_header.to_str().with_context(|| {
        format!(
            "failed to convert certificate header {:?} to string",
            certificate_header
        )
    })?;
    let structured_header = parse_structured_cert_header(certificate_str)?;
    let tree: HashTree = parse_base64_cbor(structured_header.tree)?;
    let cert: ReplicaCertificate = parse_base64_cbor(structured_header.certificate)?;

    println!("STATUS: {}", status);
    println!("ROOT HASH: {}", hex::encode(&cert.tree.digest()));
    if let Some(content_encoding) = content_encoding {
        println!("CONTENT-ENCODING: {}", content_encoding.to_str().unwrap());
    }
    println!(
        "DATA HASH: {}",
        hex::encode(&sha2::Sha256::digest(data.as_ref()))
    );
    println!("TREE HASH: {}", hex::encode(&tree.digest()));
    println!("SIGNATURE: {}", hex::encode(cert.signature.as_ref()));
    if let LookupResult::Found(mut date_bytes) = cert.tree.lookup_path(&[Label::from("time")]) {
        let timestamp_nanos = leb128::read::unsigned(&mut date_bytes)
            .with_context(|| "failed to decode certificate time as LEB128")?;
        const NANOS_PER_SEC: u64 = 1_000_000_000;

        let dt = chrono::Utc.timestamp(
            (timestamp_nanos / NANOS_PER_SEC) as i64,
            (timestamp_nanos % NANOS_PER_SEC) as u32,
        );
        println!("CERTIFICATE TIME: {}", dt.to_rfc3339());
    }
    println!("CERTIFICATE TREE: {:#?}", cert.tree);
    println!("TREE:             {:#?}", tree);
    Ok(())
}

#[test]
fn test_parse_structured_header() {
    let header = parse_structured_cert_header("certificate=:abcdef:, tree=:010203:").unwrap();
    assert_eq!(header.certificate, "abcdef");
    assert_eq!(header.tree, "010203");
}
