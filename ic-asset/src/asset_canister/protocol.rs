use candid::{CandidType, Nat};
use serde::Deserialize;

/// Create a new batch, which will expire after some time period.
/// This expiry is extended by any call to create_chunk().
/// Also, removes any expired batches.
#[derive(CandidType, Debug)]
pub struct CreateBatchRequest {}

/// The response to a CreateBatchRequest.
#[derive(CandidType, Debug, Deserialize)]
pub struct CreateBatchResponse {
    /// The ID of the created batch.
    pub batch_id: Nat,
}

/// Upload a chunk of data that is part of an asset's content.
/// Every chunk is associated with a particular batch, and will expire
#[derive(CandidType, Debug, Deserialize)]
pub struct CreateChunkRequest<'a> {
    /// The
    pub batch_id: Nat,

    ///
    #[serde(with = "serde_bytes")]
    pub content: &'a [u8],
}

#[derive(CandidType, Debug, Deserialize)]
pub struct CreateChunkResponse {
    pub chunk_id: Nat,
}

#[derive(CandidType, Debug)]
pub struct GetRequest {
    pub key: String,
    pub accept_encodings: Vec<String>,
}

#[derive(CandidType, Debug, Deserialize)]
pub struct GetResponse {
    #[serde(with = "serde_bytes")]
    pub contents: Vec<u8>,
    pub content_type: String,
    pub content_encoding: String,
}

#[derive(CandidType, Debug)]
pub struct ListAssetsRequest {}

#[derive(CandidType, Debug, Deserialize)]
pub struct AssetEncodingDetails {
    /// A content encoding, like "gzip"
    pub content_encoding: String,

    /// By convention, the sha256 of the entire asset encoding.  This is calculated
    /// by the asset uploader.  It is not generated or validated by the canister.
    pub sha256: Option<Vec<u8>>,
}

/// List returns a vec of AssetDetails
#[derive(CandidType, Debug, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

/// Create a new asset.  Has no effect if the asset already exists and the content type matches.
/// Traps if the asset already exists but with a different content type.
#[derive(CandidType, Debug)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
}

/// Set the data for a particular content encoding for the given asset.
#[derive(CandidType, Debug)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<Nat>,
    pub sha256: Option<Vec<u8>>,
}

// Remove a specific content encoding for the asset.
#[derive(CandidType, Debug)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}

/// Remove the specified asset.
#[derive(CandidType, Debug)]
pub struct DeleteAssetArguments {
    pub key: String,
}

/// Remove all assets, batches, and chunks, and reset the next batch and chunk IDs.
#[derive(CandidType, Debug)]
pub struct ClearArguments {}

#[derive(CandidType, Debug)]
pub enum BatchOperationKind {
    CreateAsset(CreateAssetArguments),

    SetAssetContent(SetAssetContentArguments),

    UnsetAssetContent(UnsetAssetContentArguments),

    DeleteAsset(DeleteAssetArguments),

    _Clear(ClearArguments),
}

/// Apply all of the operations in the batch, and then remove the batch,
#[derive(CandidType, Debug)]
pub struct CommitBatchArguments<'a> {
    pub batch_id: &'a Nat,
    pub operations: Vec<BatchOperationKind>,
}
