//! The Universal Canister (UC) is a canister built in Rust, compiled to Wasm,
//! and serves as a canister that can be used for a multitude of tests.
//!
//! Payloads to UC can execute any arbitrary sequence of system methods, making
//! it possible to test different canister behaviors without having to write up
//! custom Wat files.
use ic_agent::{Blob, CanisterId};
use std::path::Path;

/// Load the Universal Canister code from the environment and return its WASM as a blob.
pub fn wasm() -> Blob {
    let canister_env = std::env::var("IC_UNIVERSAL_CANISTER_PATH")
        .expect("Need to specify the IC_UNIVERSAL_CANISTER_PATH environment variable.");

    let canister_path = Path::new(&canister_env);

    if !canister_path.exists() {
        panic!("Could not find the universal canister WASM file.");
    } else {
        let canister_wasm = std::fs::read(&canister_path).expect("Could not read file.");

        Blob(canister_wasm)
    }
}

/// Operands used in encoding UC payloads.
#[repr(u8)]
enum Ops {
    Noop = 0,
    PushInt = 2,
    PushBytes = 3,
    ReplyDataAppend = 4,
    Reply = 5,
    Self_ = 6,
    Reject = 7,
    Caller = 8,
    CallSimple = 9,
    RejectMessage = 10,
    RejectCode = 11,
    IntToBlob = 12,
    MessagePayload = 13,
    StableSize = 15,
    StableGrow = 16,
    StableRead = 17,
    StableWrite = 18,
    DebugPrint = 19,
    Trap = 20,
    SetGlobal = 21,
    GetGlobal = 22,
}

/// A succinct shortcut for creating a `PayloadBuilder`, which is used to encode
/// instructions to be executed by the UC.
///
/// Note that a `PayloadBuilder` isn't really building Wasm as the name
/// of the shortcut here suggests, but we call it `wasm()` since it gives
/// a close enough indicator of what `PayloadBuilder` accomplishes without
/// getting into the details of how it accomplishes it.
///
/// Example usage:
/// ```
/// // Instruct the UC to reply with the bytes encoding "Hello"
/// let bytes = payload().reply_data(b"Hello").build();
/// ```
pub fn payload() -> PayloadBuilder {
    PayloadBuilder::default()
}

/// A builder class for building payloads for the universal canister.
///
/// Payloads for the UC encode `Ops` representing what instructions to
/// execute.
#[derive(Default)]
pub struct PayloadBuilder(Vec<u8>);

impl PayloadBuilder {
    fn op(mut self, b: Ops) -> Self {
        self.byte(b as u8)
    }

    fn byte(mut self, b: u8) -> Self {
        self.0.push(b);
        self
    }

    fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }

    pub fn push_int(self, int: u32) -> Self {
        self.op(Ops::PushInt).bytes(&int.to_le_bytes())
    }

    pub fn reply_data(self, data: &[u8]) -> Self {
        self.push_bytes(data).reply_data_append().reply()
    }

    pub fn reply_int(self) -> Self {
        self.int_to_blob().reply_data_append().reply()
    }

    pub fn reply_data_append(self) -> Self {
        self.op(Ops::ReplyDataAppend)
    }

    pub fn append_and_reply(self) -> Self {
        self.reply_data_append().reply()
    }

    pub fn int_to_blob(self) -> Self {
        self.op(Ops::IntToBlob)
    }

    pub fn reply(self) -> Self {
        self.op(Ops::Reply)
    }

    pub fn stable_size(self) -> Self {
        self.op(Ops::StableSize)
    }

    pub fn push_bytes(self, data: &[u8]) -> Self {
        self.op(Ops::PushBytes)
            .bytes(&(data.len() as u32).to_le_bytes())
            .bytes(data)
    }

    pub fn stable_grow(mut self, additional_pages: u32) -> Self {
        self.push_int(additional_pages).op(Ops::StableGrow)
    }

    pub fn stable_read(mut self, offset: u32, size: u32) -> Self {
        self.push_int(offset).push_int(size).op(Ops::StableRead)
    }

    pub fn stable_write(mut self, offset: u32, data: &[u8]) -> Self {
        self.push_int(offset).push_bytes(data).op(Ops::StableWrite)
    }

    /// A query from a UC to another UC.
    pub fn inter_query<P: Into<CanisterId>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "query", call_args)
    }

    /// An update from a UC to another UC.
    pub fn inter_update<P: Into<CanisterId>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "update", call_args)
    }

    pub fn call_simple<P: Into<CanisterId>>(
        mut self,
        callee: P,
        method: &str,
        call_args: CallArgs,
    ) -> Self {
        self.push_bytes(callee.into().as_bytes())
            .push_bytes(method.as_bytes())
            .push_bytes(call_args.on_reply.as_slice())
            .push_bytes(call_args.on_reject.as_slice())
            .push_bytes(call_args.other_side.as_slice())
            .op(Ops::CallSimple)
    }

    pub fn message_payload(mut self) -> Self {
        self.op(Ops::MessagePayload)
    }

    pub fn reject_message(mut self) -> Self {
        self.op(Ops::RejectMessage)
    }

    pub fn reject_code(mut self) -> Self {
        self.op(Ops::RejectCode)
    }

    pub fn reject(mut self) -> Self {
        self.op(Ops::Reject)
    }

    pub fn noop(mut self) -> Self {
        self.op(Ops::Noop)
    }

    pub fn caller(mut self) -> Self {
        self.op(Ops::Caller)
    }

    pub fn self_(mut self) -> Self {
        self.op(Ops::Self_)
    }

    /// Store data (in a global variable) on the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn set_global_data(mut self, data: &[u8]) -> Self {
        self.push_bytes(data).op(Ops::SetGlobal)
    }

    /// Get data (stored in a global variable) from the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn get_global_data(mut self) -> Self {
        self.op(Ops::GetGlobal)
    }

    pub fn debug_print(mut self, msg: &[u8]) -> Self {
        self.push_bytes(msg).op(Ops::DebugPrint)
    }

    pub fn trap_with_blob(mut self, data: &[u8]) -> Self {
        self.push_bytes(data).op(Ops::Trap)
    }

    pub fn trap(self) -> Self {
        self.trap_with_blob(&[]) // No data provided for trap.
    }

    pub fn build(self) -> Blob {
        Blob::from(self.0)
    }
}

/// Arguments to be passed into `call_simple`.
pub struct CallArgs {
    pub on_reply: Blob,
    pub on_reject: Blob,
    pub other_side: Blob,
}

impl Default for CallArgs {
    fn default() -> Self {
        Self {
            on_reply: Self::default_on_reply(),
            on_reject: Self::default_on_reject(),
            other_side: Self::default_other_side(),
        }
    }
}

impl CallArgs {
    pub fn on_reply<C: Into<Blob>>(mut self, callback: C) -> Self {
        self.on_reply = callback.into();
        self
    }

    pub fn on_reject<C: Into<Blob>>(mut self, callback: C) -> Self {
        self.on_reject = callback.into();
        self
    }

    pub fn other_side<C: Into<Blob>>(mut self, callback: C) -> Self {
        self.other_side = callback.into();
        self
    }

    // The default on_reply callback.
    // Replies to the caller with whatever arguments passed to it.
    fn default_on_reply() -> Blob {
        PayloadBuilder::default()
            .message_payload()
            .reply_data_append()
            .reply()
            .build()
    }

    // The default on_reject callback.
    // Replies to the caller with the reject code and message.
    fn default_on_reject() -> Blob {
        PayloadBuilder::default()
            .reject_code()
            .int_to_blob()
            .reply_data_append()
            .reject_message()
            .reply_data_append()
            .reply()
            .build()
    }

    // The default payload to be executed by the callee.
    // Replies with a message stating who the callee and the caller is.
    fn default_other_side() -> Blob {
        PayloadBuilder::default()
            .push_bytes(b"Hello ")
            .reply_data_append()
            .caller()
            .reply_data_append()
            .push_bytes(b" this is ")
            .reply_data_append()
            .self_()
            .reply_data_append()
            .reply()
            .build()
    }
}
