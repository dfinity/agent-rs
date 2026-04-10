#![allow(dead_code)]
//! The Universal Canister (UC) is a canister built in Rust, compiled to Wasm,
//! and serves as a canister that can be used for a multitude of tests.
//!
//! Payloads to UC can execute any arbitrary sequence of system methods, making
//! it possible to test different canister behaviors without having to write up
//! custom Wat files.
use ic_agent::export::Principal;

/// Operands used in encoding UC payloads.
#[repr(u8)]
enum Ops {
    Noop = 0,
    Drop = 1,
    PushInt = 2,
    PushBytes = 3,
    ReplyDataAppend = 4,
    Reply = 5,
    Self_ = 6,
    Reject = 7,
    Caller = 8,
    InstructionCounterIsAtLeast = 9,
    RejectMessage = 10,
    RejectCode = 11,
    IntToBlob = 12,
    MessagePayload = 13,
    Concat = 14,
    StableSize = 15,
    StableGrow = 16,
    StableRead = 17,
    StableWrite = 18,
    DebugPrint = 19,
    Trap = 20,
    SetGlobal = 21,
    GetGlobal = 22,
    BadPrint = 23,
    SetPreUpgrade = 24,
    AppendGlobal = 25,
    Time = 26,
    CyclesAvailable = 27,
    CyclesBalance = 28,
    CyclesRefunded = 29,
    AcceptCycles = 30,
    PushInt64 = 31,
    CallNew = 32,
    CallDataAppend = 33,
    CallCyclesAdd = 34,
    CallPerform = 35,
    CertifiedDataSet = 36,
    DataCertificatePresent = 37,
    DataCertificate = 38,
    CanisterStatus = 39,
    SetHeartbeat = 40,
    AcceptMessage = 41,
    SetInspectMessage = 42,
    TrapIfEq = 43,
    CallOnCleanup = 44,
    StableFill = 45,
    StableSize64 = 46,
    StableGrow64 = 47,
    StableRead64 = 48,
    StableWrite64 = 49,
    Int64ToBlob = 50,
    CyclesAvailable128 = 51,
    CyclesBalance128 = 52,
    CyclesRefunded128 = 53,
    AcceptCycles128 = 54,
    CallCyclesAdd128 = 55,
    MsgArgDataSize = 56,
    MsgArgDataCopy = 57,
    MsgCallerSize = 58,
    MsgCallerCopy = 59,
    MsgRejectMsgSize = 60,
    MsgRejectMsgCopy = 61,
    SetGlobalTimerMethod = 62,
    ApiGlobalTimerSet = 63,
    IncGlobalCounter = 64,
    GetGlobalCounter = 65,
    GetPerformanceCounter = 66,
    MsgMethodName = 67,
    ParsePrincipal = 68,
    SetTransform = 69,
    GetHttpReplyWithBody = 70,
    GetHttpTransformContext = 71,
    StableFill64 = 72,
    CanisterVersion = 73,
    TrapIfNeq = 74,
    OneWayCallNew = 76,
    IsController = 77,
    CyclesBurn128 = 78,
    BlobLength = 79,
    PushEqualBytes = 80,
    InReplicatedExecution = 81,
    CallWithBestEffortResponse = 82,
    MsgDeadline = 83,
    MemorySizeIsAtLeast = 84,
    MintCycles128 = 85,
    CostCall = 86,
    CostCreateCanister = 87,
    CostHttpRequest = 88,
    CostSignWithEcdsa = 89,
    CostSignWithSchnorr = 90,
    CostVetkdDeriveKey = 91,
    LiquidCyclesBalance128 = 92,
    CallDataAppendCyclesAddMax = 93,
    RootKey = 94,
    SetOnLowWasmMemoryMethod = 95,
    WasmMemoryGrow = 96,
    CostHttpRequestV2 = 97,
}

/// A succinct shortcut for creating a `PayloadBuilder`, which is used to encode
/// instructions to be executed by the UC.
///
/// Example usage:
/// ```
/// use ref_tests::universal_canister::payload;
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
    fn op(self, b: Ops) -> Self {
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

    pub fn push_int64(self, int: u64) -> Self {
        self.op(Ops::PushInt64).bytes(&int.to_le_bytes())
    }

    pub fn push_bytes(self, data: &[u8]) -> Self {
        self.op(Ops::PushBytes)
            .bytes(&(data.len() as u32).to_le_bytes())
            .bytes(data)
    }

    /// Push a blob of `length` bytes all set to `byte`.
    pub fn push_equal_bytes(self, byte: u8, length: u32) -> Self {
        self.push_int(byte as u32)
            .push_int(length)
            .op(Ops::PushEqualBytes)
    }

    // --- Stack manipulation ---

    /// Drop the top value from the stack.
    pub fn drop(self) -> Self {
        self.op(Ops::Drop)
    }

    /// Concatenate the top two blobs on the stack.
    pub fn concat(self) -> Self {
        self.op(Ops::Concat)
    }

    /// Push the byte length of the top blob onto the stack as an i32.
    pub fn blob_length(self) -> Self {
        self.op(Ops::BlobLength)
    }

    // --- Type conversions ---

    pub fn int_to_blob(self) -> Self {
        self.op(Ops::IntToBlob)
    }

    pub fn int64_to_blob(self) -> Self {
        self.op(Ops::Int64ToBlob)
    }

    // --- Reply/reject ---

    pub fn reply_data_append(self) -> Self {
        self.op(Ops::ReplyDataAppend)
    }

    pub fn append_and_reply(self) -> Self {
        self.reply_data_append().reply()
    }

    pub fn reply(self) -> Self {
        self.op(Ops::Reply)
    }

    /// Convenience: push `data`, append it to the reply buffer, and reply.
    pub fn reply_data(self, data: &[u8]) -> Self {
        self.push_bytes(data).reply_data_append().reply()
    }

    /// Convenience: convert the top i32 to a blob and reply with it.
    pub fn reply_int(self) -> Self {
        self.int_to_blob().reply_data_append().reply()
    }

    pub fn reject(self) -> Self {
        self.op(Ops::Reject)
    }

    // --- Canister identity ---

    /// Push this canister's own principal as a blob.
    pub fn self_(self) -> Self {
        self.op(Ops::Self_)
    }

    /// Push the caller's principal as a blob.
    pub fn caller(self) -> Self {
        self.op(Ops::Caller)
    }

    // --- Message payload ---

    /// Push the full argument data of the current message.
    pub fn message_payload(self) -> Self {
        self.op(Ops::MessagePayload)
    }

    pub fn reject_message(self) -> Self {
        self.op(Ops::RejectMessage)
    }

    pub fn reject_code(self) -> Self {
        self.op(Ops::RejectCode)
    }

    /// Push the method name of the current message as a blob.
    pub fn msg_method_name(self) -> Self {
        self.op(Ops::MsgMethodName)
    }

    /// Push the argument data size.
    pub fn msg_arg_data_size(self) -> Self {
        self.op(Ops::MsgArgDataSize)
    }

    /// Pop offset (i32) and size (i32), push the corresponding slice of arg data.
    pub fn msg_arg_data_copy(self) -> Self {
        self.op(Ops::MsgArgDataCopy)
    }

    /// Push the caller size.
    pub fn msg_caller_size(self) -> Self {
        self.op(Ops::MsgCallerSize)
    }

    /// Pop offset (i32) and size (i32), push the corresponding slice of the caller blob.
    pub fn msg_caller_copy(self) -> Self {
        self.op(Ops::MsgCallerCopy)
    }

    /// Push the reject message size.
    pub fn msg_reject_msg_size(self) -> Self {
        self.op(Ops::MsgRejectMsgSize)
    }

    /// Pop offset (i32) and size (i32), push the corresponding slice of the reject message.
    pub fn msg_reject_msg_copy(self) -> Self {
        self.op(Ops::MsgRejectMsgCopy)
    }

    // --- Global data ---

    /// Store data (in a global variable) on the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn set_global_data(self, data: &[u8]) -> Self {
        self.push_bytes(data).op(Ops::SetGlobal)
    }

    /// Append to data stored in the global variable.
    pub fn append_global_data(self, data: &[u8]) -> Self {
        self.push_bytes(data).op(Ops::AppendGlobal)
    }

    /// Get data (stored in a global variable) from the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn get_global_data(self) -> Self {
        self.op(Ops::GetGlobal)
    }

    /// Increment the persistent global counter.
    pub fn inc_global_counter(self) -> Self {
        self.op(Ops::IncGlobalCounter)
    }

    /// Push the current value of the persistent global counter as an i64.
    pub fn get_global_counter(self) -> Self {
        self.op(Ops::GetGlobalCounter)
    }

    // --- Time and timers ---

    /// Push the current time as an i64 (nanoseconds since epoch).
    pub fn time(self) -> Self {
        self.op(Ops::Time)
    }

    /// Pop a timestamp i64 from the stack, set the global timer, push the previous deadline i64.
    pub fn api_global_timer_set(self) -> Self {
        self.op(Ops::ApiGlobalTimerSet)
    }

    /// Convenience: set the global timer to `timestamp`.
    pub fn global_timer_set(self, timestamp: u64) -> Self {
        self.push_int64(timestamp).op(Ops::ApiGlobalTimerSet)
    }

    /// Set the payload to execute when the global timer fires.
    pub fn set_global_timer_method(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetGlobalTimerMethod)
    }

    // --- System hooks ---

    /// Set the payload to execute in `canister_pre_upgrade`.
    pub fn set_pre_upgrade(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetPreUpgrade)
    }

    /// Set the payload to execute in `canister_heartbeat`.
    pub fn set_heartbeat(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetHeartbeat)
    }

    /// Set the payload to execute in `canister_inspect_message`.
    pub fn set_inspect_message(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetInspectMessage)
    }

    /// Set the payload to execute in `canister_on_low_wasm_memory`.
    pub fn set_on_low_wasm_memory_method(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetOnLowWasmMemoryMethod)
    }

    /// Set the HTTP transform function payload.
    pub fn set_transform(self, code: &[u8]) -> Self {
        self.push_bytes(code).op(Ops::SetTransform)
    }

    /// Accept the current inspected message (used in `inspect_message` handler).
    pub fn accept_message(self) -> Self {
        self.op(Ops::AcceptMessage)
    }

    // --- Canister info ---

    /// Push the canister status as an i32.
    pub fn canister_status(self) -> Self {
        self.op(Ops::CanisterStatus)
    }

    /// Push the canister version as an i64.
    pub fn canister_version(self) -> Self {
        self.op(Ops::CanisterVersion)
    }

    /// Push the IC root key as a blob.
    pub fn root_key(self) -> Self {
        self.op(Ops::RootKey)
    }

    /// Pop a principal blob and push 1 if it is a controller of this canister, 0 otherwise.
    pub fn is_controller(self) -> Self {
        self.op(Ops::IsController)
    }

    /// Push 1 if running in replicated execution, 0 otherwise.
    pub fn in_replicated_execution(self) -> Self {
        self.op(Ops::InReplicatedExecution)
    }

    // --- Performance ---

    /// Pop a counter type i32, push the performance counter value as an i64.
    pub fn get_performance_counter(self) -> Self {
        self.op(Ops::GetPerformanceCounter)
    }

    /// Spin until the instruction counter reaches `amount`.
    pub fn instruction_counter_is_at_least(self, amount: u64) -> Self {
        self.push_int64(amount).op(Ops::InstructionCounterIsAtLeast)
    }

    // --- Memory ---

    /// Allocate Wasm memory pages until at least `target` bytes of Wasm memory are present.
    pub fn memory_size_is_at_least(self, target: u64) -> Self {
        self.push_int64(target).op(Ops::MemorySizeIsAtLeast)
    }

    /// Grow Wasm linear memory by `pages` pages (wasm32 only; no-op on other targets).
    pub fn wasm_memory_grow(self, pages: u32) -> Self {
        self.push_int(pages).op(Ops::WasmMemoryGrow)
    }

    // --- Stable memory (32-bit API) ---

    pub fn stable_size(self) -> Self {
        self.op(Ops::StableSize)
    }

    pub fn stable_grow(self, additional_pages: u32) -> Self {
        self.push_int(additional_pages).op(Ops::StableGrow)
    }

    pub fn stable_read(self, offset: u32, size: u32) -> Self {
        self.push_int(offset).push_int(size).op(Ops::StableRead)
    }

    pub fn stable_write(self, offset: u32, data: &[u8]) -> Self {
        self.push_int(offset).push_bytes(data).op(Ops::StableWrite)
    }

    /// Fill `length` bytes of stable memory starting at `offset` with `byte`.
    pub fn stable_fill(self, offset: u32, byte: u8, length: u32) -> Self {
        self.push_int(offset)
            .push_int(byte as u32)
            .push_int(length)
            .op(Ops::StableFill)
    }

    // --- Stable memory (64-bit API) ---

    pub fn stable64_size(self) -> Self {
        self.op(Ops::StableSize64)
    }

    pub fn stable64_grow(self, additional_pages: u64) -> Self {
        self.push_int64(additional_pages).op(Ops::StableGrow64)
    }

    pub fn stable64_read(self, offset: u64, size: u64) -> Self {
        self.push_int64(offset)
            .push_int64(size)
            .op(Ops::StableRead64)
    }

    pub fn stable64_write(self, offset: u64, data: &[u8]) -> Self {
        self.push_int64(offset)
            .push_bytes(data)
            .op(Ops::StableWrite64)
    }

    /// Fill `length` bytes of stable memory starting at `offset` with `byte` (64-bit API).
    pub fn stable64_fill(self, offset: u64, byte: u8, length: u64) -> Self {
        self.push_int64(offset)
            .push_int64(byte as u64)
            .push_int64(length)
            .op(Ops::StableFill64)
    }

    // --- Cycles (64-bit) ---

    /// Push cycles available in the current call as an i64.
    pub fn cycles_available(self) -> Self {
        self.op(Ops::CyclesAvailable)
    }

    /// Push canister cycle balance as an i64.
    pub fn cycles_balance(self) -> Self {
        self.op(Ops::CyclesBalance)
    }

    /// Push cycles refunded in the current response as an i64.
    pub fn cycles_refunded(self) -> Self {
        self.op(Ops::CyclesRefunded)
    }

    /// Pop an i64 amount and accept that many cycles; push the actually accepted amount as i64.
    pub fn accept_cycles(self) -> Self {
        self.op(Ops::AcceptCycles)
    }

    // --- Cycles (128-bit) ---

    /// Push cycles available in the current call as a 16-byte little-endian blob.
    pub fn cycles_available128(self) -> Self {
        self.op(Ops::CyclesAvailable128)
    }

    /// Push canister cycle balance as a 16-byte little-endian blob.
    pub fn cycles_balance128(self) -> Self {
        self.op(Ops::CyclesBalance128)
    }

    /// Push liquid canister cycle balance as a 16-byte little-endian blob.
    pub fn liquid_cycles_balance128(self) -> Self {
        self.op(Ops::LiquidCyclesBalance128)
    }

    /// Push cycles refunded in the current response as a 16-byte little-endian blob.
    pub fn cycles_refunded128(self) -> Self {
        self.op(Ops::CyclesRefunded128)
    }

    /// Pop high i64 and low i64, accept up to that many cycles; push accepted amount as 16-byte blob.
    pub fn accept_cycles128(self) -> Self {
        self.op(Ops::AcceptCycles128)
    }

    /// Convenience: accept up to `amount` cycles (128-bit).
    pub fn accept_cycles128_amount(self, amount: u128) -> Self {
        let high = (amount >> 64) as u64;
        let low = amount as u64;
        self.push_int64(high).push_int64(low).accept_cycles128()
    }

    /// Pop high i64 and low i64, mint that many cycles (NNS/CMC only); push result as 16-byte blob.
    pub fn mint_cycles128(self) -> Self {
        self.op(Ops::MintCycles128)
    }

    /// Pop high i64 and low i64, burn that many cycles; push result as 16-byte blob.
    pub fn cycles_burn128(self) -> Self {
        self.op(Ops::CyclesBurn128)
    }

    // --- Inter-canister calls ---

    /// A query from a UC to another UC.
    pub fn inter_query<P: Into<Principal>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "query", call_args)
    }

    /// An update from a UC to another UC.
    pub fn inter_update<P: Into<Principal>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "update", call_args)
    }

    /// Build a call to `callee.method` with the given callbacks and payload, then perform it.
    pub fn call_simple<P: Into<Principal>>(
        self,
        callee: P,
        method: &str,
        call_args: CallArgs,
    ) -> Self {
        self.push_bytes(callee.into().as_slice())
            .push_bytes(method.as_bytes())
            .push_bytes(call_args.on_reply.as_slice())
            .push_bytes(call_args.on_reject.as_slice())
            .op(Ops::CallNew)
            .push_bytes(call_args.other_side.as_slice())
            .op(Ops::CallDataAppend)
            .op(Ops::CallPerform)
    }

    /// A fire-and-forget call (no reply/reject callbacks).
    pub fn one_way_call<P: Into<Principal>>(self, callee: P, method: &str, payload: &[u8]) -> Self {
        self.push_bytes(callee.into().as_slice())
            .push_bytes(method.as_bytes())
            .op(Ops::OneWayCallNew)
            .push_bytes(payload)
            .op(Ops::CallDataAppend)
            .op(Ops::CallPerform)
    }

    /// Low-level: pop callee blob, method blob, on_reply blob, on_reject blob; initiate a call.
    /// Follow with `call_data_append`, optional `call_cycles_add*`, `call_on_cleanup`,
    /// `call_with_best_effort_response`, then `call_perform`.
    pub fn call_new(self) -> Self {
        self.op(Ops::CallNew)
    }

    /// Low-level: pop a blob and append it to the pending call's argument data.
    pub fn call_data_append(self) -> Self {
        self.op(Ops::CallDataAppend)
    }

    /// Low-level: pop an i64 amount and add that many cycles to the pending call.
    pub fn call_cycles_add(self) -> Self {
        self.op(Ops::CallCyclesAdd)
    }

    /// Convenience: add `amount` cycles to the pending call (64-bit).
    pub fn call_cycles_add_amount(self, amount: u64) -> Self {
        self.push_int64(amount).call_cycles_add()
    }

    /// Low-level: pop high i64 and low i64, add that many cycles to the pending call (128-bit).
    pub fn call_cycles_add128(self) -> Self {
        self.op(Ops::CallCyclesAdd128)
    }

    /// Convenience: add `amount` cycles to the pending call (128-bit).
    pub fn call_cycles_add128_amount(self, amount: u128) -> Self {
        let high = (amount >> 64) as u64;
        let low = amount as u64;
        self.push_int64(high).push_int64(low).call_cycles_add128()
    }

    /// Low-level: pop payload blob and method_name_size i64; append payload and add max liquid
    /// cycles (after accounting for call cost) to the pending call.
    pub fn call_data_append_cycles_add_max(self) -> Self {
        self.op(Ops::CallDataAppendCyclesAddMax)
    }

    /// Low-level: pop a cleanup-code blob and register it as the call cleanup handler.
    pub fn call_on_cleanup(self) -> Self {
        self.op(Ops::CallOnCleanup)
    }

    /// Low-level: pop a timeout_seconds i32 and mark this call as best-effort with that timeout.
    pub fn call_with_best_effort_response(self) -> Self {
        self.op(Ops::CallWithBestEffortResponse)
    }

    /// Convenience: mark the pending call as best-effort with `timeout_seconds`.
    pub fn call_with_best_effort_response_timeout(self, timeout_seconds: u32) -> Self {
        self.push_int(timeout_seconds)
            .call_with_best_effort_response()
    }

    /// Low-level: perform the pending call. Traps if `call_perform` returns a non-zero error code.
    pub fn call_perform(self) -> Self {
        self.op(Ops::CallPerform)
    }

    /// Push the message deadline as an i64 (nanoseconds). Only meaningful for best-effort calls.
    pub fn msg_deadline(self) -> Self {
        self.op(Ops::MsgDeadline)
    }

    // --- Certified data ---

    /// Pop a blob and set it as the certified data.
    pub fn certified_data_set(self) -> Self {
        self.op(Ops::CertifiedDataSet)
    }

    /// Convenience: set certified data to `data`.
    pub fn certified_data_set_bytes(self, data: &[u8]) -> Self {
        self.push_bytes(data).certified_data_set()
    }

    /// Push 1 if a data certificate is present, 0 otherwise.
    pub fn data_certificate_present(self) -> Self {
        self.op(Ops::DataCertificatePresent)
    }

    /// Push the data certificate blob.
    pub fn data_certificate(self) -> Self {
        self.op(Ops::DataCertificate)
    }

    // --- HTTP outcalls ---

    /// Pop a body blob; push a Candid-encoded `HttpResponse { status: 200, body }`.
    pub fn get_http_reply_with_body(self) -> Self {
        self.op(Ops::GetHttpReplyWithBody)
    }

    /// Pop a Candid-encoded `TransformArg` blob; push the `context` field.
    pub fn get_http_transform_context(self) -> Self {
        self.op(Ops::GetHttpTransformContext)
    }

    // --- Cost queries ---

    /// Pop method_name_size i64 and payload_size i64; push call cost as 16-byte blob.
    pub fn cost_call(self) -> Self {
        self.op(Ops::CostCall)
    }

    /// Push the cost of creating a canister as a 16-byte blob.
    pub fn cost_create_canister(self) -> Self {
        self.op(Ops::CostCreateCanister)
    }

    /// Pop request_size i64 and max_res_bytes i64; push HTTP request cost as 16-byte blob.
    pub fn cost_http_request(self) -> Self {
        self.op(Ops::CostHttpRequest)
    }

    /// Pop a Candid-encoded params blob; push HTTP request cost as 16-byte blob (v2).
    pub fn cost_http_request_v2(self) -> Self {
        self.op(Ops::CostHttpRequestV2)
    }

    /// Pop key_name blob and ecdsa_curve i32; push ECDSA signing cost as 16-byte blob.
    /// Traps if the curve is invalid.
    pub fn cost_sign_with_ecdsa(self) -> Self {
        self.op(Ops::CostSignWithEcdsa)
    }

    /// Pop key_name blob and algorithm i32; push Schnorr signing cost as 16-byte blob.
    /// Traps if the algorithm is invalid.
    pub fn cost_sign_with_schnorr(self) -> Self {
        self.op(Ops::CostSignWithSchnorr)
    }

    /// Pop key_name blob and vetkd_curve i32; push vetKD key derivation cost as 16-byte blob.
    /// Traps if the curve is invalid.
    pub fn cost_vetkd_derive_key(self) -> Self {
        self.op(Ops::CostVetkdDeriveKey)
    }

    // --- Control flow / traps ---

    pub fn noop(self) -> Self {
        self.op(Ops::Noop)
    }

    pub fn debug_print(self, msg: &[u8]) -> Self {
        self.push_bytes(msg).op(Ops::DebugPrint)
    }

    pub fn trap_with_blob(self, data: &[u8]) -> Self {
        self.push_bytes(data).op(Ops::Trap)
    }

    pub fn trap(self) -> Self {
        self.trap_with_blob(&[])
    }

    /// Pop blobs `a`, `b`, and `msg`; trap with `msg` if `a == b`.
    pub fn trap_if_eq(self) -> Self {
        self.op(Ops::TrapIfEq)
    }

    /// Pop blobs `a`, `b`, and `msg`; trap with `msg` if `a != b`.
    pub fn trap_if_neq(self) -> Self {
        self.op(Ops::TrapIfNeq)
    }

    /// Issue a debug_print with an out-of-bounds pointer (tests error handling).
    pub fn bad_print(self) -> Self {
        self.op(Ops::BadPrint)
    }

    // --- Principal utilities ---

    /// Pop a principal-bytes blob; push its text representation as a blob.
    pub fn parse_principal(self) -> Self {
        self.op(Ops::ParsePrincipal)
    }

    pub fn build(self) -> Vec<u8> {
        self.0
    }
}

/// Arguments to be passed into `call_simple`.
pub struct CallArgs {
    pub on_reply: Vec<u8>,
    pub on_reject: Vec<u8>,
    pub other_side: Vec<u8>,
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
    pub fn on_reply<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.on_reply = callback.into();
        self
    }

    pub fn on_reject<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.on_reject = callback.into();
        self
    }

    pub fn other_side<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.other_side = callback.into();
        self
    }

    // The default on_reply callback.
    // Replies to the caller with whatever arguments passed to it.
    fn default_on_reply() -> Vec<u8> {
        PayloadBuilder::default()
            .message_payload()
            .reply_data_append()
            .reply()
            .build()
    }

    // The default on_reject callback.
    // Replies to the caller with the reject code and message.
    fn default_on_reject() -> Vec<u8> {
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
    fn default_other_side() -> Vec<u8> {
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
