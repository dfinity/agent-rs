use candid::{CandidType, Nat};
use serde::Deserialize;

#[derive(CandidType, Debug)]
pub struct CreateBatchRequest {}

#[derive(CandidType, Debug, Deserialize)]
pub struct CreateBatchResponse {
    pub batch_id: Nat,
}

#[derive(CandidType, Debug, Deserialize)]
pub struct CreateChunkRequest<'a> {
    pub batch_id: Nat,
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
    pub content_encoding: String,
    pub sha256: Option<Vec<u8>>,
}

#[derive(CandidType, Debug, Deserialize)]
pub struct AssetDetails {
    pub key: String,
    pub encodings: Vec<AssetEncodingDetails>,
    pub content_type: String,
}

#[derive(CandidType, Debug)]
pub struct CreateAssetArguments {
    pub key: String,
    pub content_type: String,
}
#[derive(CandidType, Debug)]
pub struct SetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
    pub chunk_ids: Vec<Nat>,
    pub sha256: Option<Vec<u8>>,
}
#[derive(CandidType, Debug)]
pub struct UnsetAssetContentArguments {
    pub key: String,
    pub content_encoding: String,
}
#[derive(CandidType, Debug)]
pub struct DeleteAssetArguments {
    pub key: String,
}
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

#[derive(CandidType, Debug)]
pub struct CommitBatchArguments<'a> {
    pub batch_id: &'a Nat,
    pub operations: Vec<BatchOperationKind>,
}
