//! Checked wrappers around certain numeric values used in management calls.

use thiserror::Error;

/// An error encountered when attempting to construct a [`ComputeAllocation`].
#[derive(Error, Debug)]
pub enum ComputeAllocationError {
    /// The provided value was not a percentage in the range [0, 100].
    #[error("Must be a percent between 0 and 100.")]
    MustBeAPercentage(),
}

/// A compute allocation for a canister, represented as a percentage between 0 and 100 inclusive.
///
/// This represents the percentage of a canister's maximum compute capacity that the IC should commit to guaranteeing for the canister.
/// If 0, computation is provided on a best-effort basis.
#[derive(Copy, Clone, Debug)]
pub struct ComputeAllocation(u8);

impl std::convert::From<ComputeAllocation> for u8 {
    fn from(compute_allocation: ComputeAllocation) -> Self {
        compute_allocation.0
    }
}

macro_rules! try_from_compute_alloc_decl {
    ( $t: ty ) => {
        impl std::convert::TryFrom<$t> for ComputeAllocation {
            type Error = ComputeAllocationError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                if (value as i64) < 0 || (value as i64) > 100 {
                    Err(ComputeAllocationError::MustBeAPercentage())
                } else {
                    Ok(Self(value as u8))
                }
            }
        }
    };
}

try_from_compute_alloc_decl!(u8);
try_from_compute_alloc_decl!(u16);
try_from_compute_alloc_decl!(u32);
try_from_compute_alloc_decl!(u64);
try_from_compute_alloc_decl!(i8);
try_from_compute_alloc_decl!(i16);
try_from_compute_alloc_decl!(i32);
try_from_compute_alloc_decl!(i64);

/// An error encountered when attempting to construct a [`MemoryAllocation`].
#[derive(Error, Debug)]
pub enum MemoryAllocationError {
    /// The provided value was not in the range [0, 2^48] (i.e. 256 TiB).
    #[error("Memory allocation must be between 0 and 2^48 (i.e 256TiB), inclusively. Got {0}.")]
    InvalidMemorySize(u64),
}

/// A memory allocation for a canister. Can be anywhere from 0 to 2^48 (i.e. 256 TiB) inclusive.
///
/// This represents the size, in bytes, that the IC guarantees to the canister and limits the canister to.
/// If a canister attempts to exceed this value (and the value is nonzero), the attempt will fail. If 0,
/// memory allocation is provided on a best-effort basis.
#[derive(Copy, Clone, Debug)]
pub struct MemoryAllocation(u64);

impl std::convert::From<MemoryAllocation> for u64 {
    fn from(memory_allocation: MemoryAllocation) -> Self {
        memory_allocation.0
    }
}

macro_rules! try_from_memory_alloc_decl {
    ( $t: ty ) => {
        impl std::convert::TryFrom<$t> for MemoryAllocation {
            type Error = MemoryAllocationError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                if (value as i64) < 0 || (value as i64) > (1i64 << 48) {
                    Err(MemoryAllocationError::InvalidMemorySize(value as u64))
                } else {
                    Ok(Self(value as u64))
                }
            }
        }
    };
}

try_from_memory_alloc_decl!(u8);
try_from_memory_alloc_decl!(u16);
try_from_memory_alloc_decl!(u32);
try_from_memory_alloc_decl!(u64);
try_from_memory_alloc_decl!(i8);
try_from_memory_alloc_decl!(i16);
try_from_memory_alloc_decl!(i32);
try_from_memory_alloc_decl!(i64);

/// An error encountered when attempting to construct a [`FreezingThreshold`].
#[derive(Error, Debug)]
pub enum FreezingThresholdError {
    /// The provided value was not in the range [0, 2^64-1].
    #[error("Freezing threshold must be between 0 and 2^64-1, inclusively. Got {0}.")]
    InvalidFreezingThreshold(u64),
}

/// A freezing threshold for a canister. Can be anywhere from 0 to 2^64-1 inclusive.
///
/// This represents the time, in seconds, of 'runway' the IC tries to guarantee the canister.
/// If the canister's persistent costs, like storage, will likely lead it to run out of cycles within this amount of time,
/// then the IC will 'freeze' the canister. Attempts to call its methods will be rejected unconditionally.
/// The canister also cannot make any calls that push its cycle count into freezing threshold range.
#[derive(Copy, Clone, Debug)]
pub struct FreezingThreshold(u64);

impl std::convert::From<FreezingThreshold> for u64 {
    fn from(freezing_threshold: FreezingThreshold) -> Self {
        freezing_threshold.0
    }
}

macro_rules! try_from_freezing_threshold_decl {
    ( $t: ty ) => {
        impl std::convert::TryFrom<$t> for FreezingThreshold {
            type Error = FreezingThresholdError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                if (value as i128) < 0 || (value as i128) > (2_i128.pow(64) - 1i128) {
                    Err(FreezingThresholdError::InvalidFreezingThreshold(
                        value as u64,
                    ))
                } else {
                    Ok(Self(value as u64))
                }
            }
        }
    };
}

try_from_freezing_threshold_decl!(u8);
try_from_freezing_threshold_decl!(u16);
try_from_freezing_threshold_decl!(u32);
try_from_freezing_threshold_decl!(u64);
try_from_freezing_threshold_decl!(i8);
try_from_freezing_threshold_decl!(i16);
try_from_freezing_threshold_decl!(i32);
try_from_freezing_threshold_decl!(i64);
try_from_freezing_threshold_decl!(i128);
try_from_freezing_threshold_decl!(u128);

/// An error encountered when attempting to construct a [`ReservedCyclesLimit`].
#[derive(Error, Debug)]
pub enum ReservedCyclesLimitError {
    /// The provided value was not in the range [0, 2^128-1].
    #[error("ReservedCyclesLimit must be between 0 and 2^128-1, inclusively. Got {0}.")]
    InvalidReservedCyclesLimit(i128),
}

/// A reserved cycles limit for a canister. Can be anywhere from 0 to 2^128-1 inclusive.
///
/// This represents the upper limit of `reserved_cycles` for the canister.
///
/// Reserved cycles are cycles that the system sets aside for future use by the canister.
/// If a subnet's storage exceeds 450 GiB, then every time a canister allocates new storage bytes,
/// the system sets aside some amount of cycles from the main balance of the canister.
/// These reserved cycles will be used to cover future payments for the newly allocated bytes.
/// The reserved cycles are not transferable and the amount of reserved cycles depends on how full the subnet is.
///
/// A reserved cycles limit of 0 disables the reservation mechanism for the canister.
/// If so disabled, the canister will trap when it tries to allocate storage, if the subnet's usage exceeds 450 GiB.
#[derive(Copy, Clone, Debug)]
pub struct ReservedCyclesLimit(u128);

impl std::convert::From<ReservedCyclesLimit> for u128 {
    fn from(reserved_cycles_limit: ReservedCyclesLimit) -> Self {
        reserved_cycles_limit.0
    }
}

#[allow(unused_comparisons)]
macro_rules! try_from_reserved_cycles_limit_decl {
    ( $t: ty ) => {
        impl std::convert::TryFrom<$t> for ReservedCyclesLimit {
            type Error = ReservedCyclesLimitError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                #[allow(unused_comparisons)]
                if value < 0 {
                    Err(ReservedCyclesLimitError::InvalidReservedCyclesLimit(
                        value as i128,
                    ))
                } else {
                    Ok(Self(value as u128))
                }
            }
        }
    };
}

try_from_reserved_cycles_limit_decl!(u8);
try_from_reserved_cycles_limit_decl!(u16);
try_from_reserved_cycles_limit_decl!(u32);
try_from_reserved_cycles_limit_decl!(u64);
try_from_reserved_cycles_limit_decl!(i8);
try_from_reserved_cycles_limit_decl!(i16);
try_from_reserved_cycles_limit_decl!(i32);
try_from_reserved_cycles_limit_decl!(i64);
try_from_reserved_cycles_limit_decl!(i128);
try_from_reserved_cycles_limit_decl!(u128);

/// An error encountered when attempting to construct a [`WasmMemoryLimit`].
#[derive(Error, Debug)]
pub enum WasmMemoryLimitError {
    /// The provided value was not in the range [0, 2^48] (i.e. 256 TiB).
    #[error("Wasm memory limit must be between 0 and 2^48 (i.e 256TiB), inclusively. Got {0}.")]
    InvalidMemoryLimit(i64),
}

/// A soft limit on the Wasm memory usage of the canister. Update calls,
/// timers, heartbeats, install, and post-upgrade fail if the Wasm memory
/// usage exceeds this limit. The main purpose of this field is to protect
/// against the case when the canister reaches the hard 4GiB limit.
/// Must be a number between 0 and 2^48^ (i.e 256TB), inclusively.
#[derive(Copy, Clone, Debug)]
pub struct WasmMemoryLimit(u64);

impl std::convert::From<WasmMemoryLimit> for u64 {
    fn from(wasm_memory_limit: WasmMemoryLimit) -> Self {
        wasm_memory_limit.0
    }
}

macro_rules! try_from_wasm_memory_limit_decl {
    ( $t: ty ) => {
        impl std::convert::TryFrom<$t> for WasmMemoryLimit {
            type Error = WasmMemoryLimitError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                if (value as i64) < 0 || (value as i64) > (1i64 << 48) {
                    Err(Self::Error::InvalidMemoryLimit(value as i64))
                } else {
                    Ok(Self(value as u64))
                }
            }
        }
    };
}

try_from_wasm_memory_limit_decl!(u8);
try_from_wasm_memory_limit_decl!(u16);
try_from_wasm_memory_limit_decl!(u32);
try_from_wasm_memory_limit_decl!(u64);
try_from_wasm_memory_limit_decl!(i8);
try_from_wasm_memory_limit_decl!(i16);
try_from_wasm_memory_limit_decl!(i32);
try_from_wasm_memory_limit_decl!(i64);

#[test]
#[allow(clippy::useless_conversion)]
fn can_convert_compute_allocation() {
    use std::convert::{TryFrom, TryInto};

    // This is more of a compiler test than an actual test.
    let _ca_u8: ComputeAllocation = 1u8.try_into().unwrap();
    let _ca_u16: ComputeAllocation = 1u16.try_into().unwrap();
    let _ca_u32: ComputeAllocation = 1u32.try_into().unwrap();
    let _ca_u64: ComputeAllocation = 1u64.try_into().unwrap();
    let _ca_i8: ComputeAllocation = 1i8.try_into().unwrap();
    let _ca_i16: ComputeAllocation = 1i16.try_into().unwrap();
    let _ca_i32: ComputeAllocation = 1i32.try_into().unwrap();
    let _ca_i64: ComputeAllocation = 1i64.try_into().unwrap();

    let ca = ComputeAllocation(100);
    let _ca_ca: ComputeAllocation = ComputeAllocation::try_from(ca).unwrap();
}

#[test]
#[allow(clippy::useless_conversion)]
fn can_convert_memory_allocation() {
    use std::convert::{TryFrom, TryInto};

    // This is more of a compiler test than an actual test.
    let _ma_u8: MemoryAllocation = 1u8.try_into().unwrap();
    let _ma_u16: MemoryAllocation = 1u16.try_into().unwrap();
    let _ma_u32: MemoryAllocation = 1u32.try_into().unwrap();
    let _ma_u64: MemoryAllocation = 1u64.try_into().unwrap();
    let _ma_i8: MemoryAllocation = 1i8.try_into().unwrap();
    let _ma_i16: MemoryAllocation = 1i16.try_into().unwrap();
    let _ma_i32: MemoryAllocation = 1i32.try_into().unwrap();
    let _ma_i64: MemoryAllocation = 1i64.try_into().unwrap();

    let ma = MemoryAllocation(100);
    let _ma_ma: MemoryAllocation = MemoryAllocation::try_from(ma).unwrap();
}

#[test]
#[allow(clippy::useless_conversion)]
fn can_convert_freezing_threshold() {
    use std::convert::{TryFrom, TryInto};

    // This is more of a compiler test than an actual test.
    let _ft_u8: FreezingThreshold = 1u8.try_into().unwrap();
    let _ft_u16: FreezingThreshold = 1u16.try_into().unwrap();
    let _ft_u32: FreezingThreshold = 1u32.try_into().unwrap();
    let _ft_u64: FreezingThreshold = 1u64.try_into().unwrap();
    let _ft_i8: FreezingThreshold = 1i8.try_into().unwrap();
    let _ft_i16: FreezingThreshold = 1i16.try_into().unwrap();
    let _ft_i32: FreezingThreshold = 1i32.try_into().unwrap();
    let _ft_i64: FreezingThreshold = 1i64.try_into().unwrap();
    let _ft_u128: FreezingThreshold = 1i128.try_into().unwrap();
    let _ft_i128: FreezingThreshold = 1u128.try_into().unwrap();

    let ft = FreezingThreshold(100);
    let _ft_ft: FreezingThreshold = FreezingThreshold::try_from(ft).unwrap();
}

#[test]
#[allow(clippy::useless_conversion)]
fn can_convert_reserved_cycles_limit() {
    use std::convert::{TryFrom, TryInto};

    // This is more of a compiler test than an actual test.
    let _ft_u8: ReservedCyclesLimit = 1u8.try_into().unwrap();
    let _ft_u16: ReservedCyclesLimit = 1u16.try_into().unwrap();
    let _ft_u32: ReservedCyclesLimit = 1u32.try_into().unwrap();
    let _ft_u64: ReservedCyclesLimit = 1u64.try_into().unwrap();
    let _ft_i8: ReservedCyclesLimit = 1i8.try_into().unwrap();
    let _ft_i16: ReservedCyclesLimit = 1i16.try_into().unwrap();
    let _ft_i32: ReservedCyclesLimit = 1i32.try_into().unwrap();
    let _ft_i64: ReservedCyclesLimit = 1i64.try_into().unwrap();
    let _ft_u128: ReservedCyclesLimit = 1i128.try_into().unwrap();
    let _ft_i128: ReservedCyclesLimit = 1u128.try_into().unwrap();

    assert!(matches!(
        ReservedCyclesLimit::try_from(-4).unwrap_err(),
        ReservedCyclesLimitError::InvalidReservedCyclesLimit(-4)
    ));

    assert_eq!(
        ReservedCyclesLimit::try_from(2u128.pow(127) + 6).unwrap().0,
        170_141_183_460_469_231_731_687_303_715_884_105_734_u128
    );

    let ft = ReservedCyclesLimit(100);
    let _ft_ft: ReservedCyclesLimit = ReservedCyclesLimit::try_from(ft).unwrap();
}

#[test]
#[allow(clippy::useless_conversion)]
fn can_convert_wasm_memory_limit() {
    use std::convert::{TryFrom, TryInto};

    // This is more of a compiler test than an actual test.
    let _ma_u8: WasmMemoryLimit = 1u8.try_into().unwrap();
    let _ma_u16: WasmMemoryLimit = 1u16.try_into().unwrap();
    let _ma_u32: WasmMemoryLimit = 1u32.try_into().unwrap();
    let _ma_u64: WasmMemoryLimit = 1u64.try_into().unwrap();
    let _ma_i8: WasmMemoryLimit = 1i8.try_into().unwrap();
    let _ma_i16: WasmMemoryLimit = 1i16.try_into().unwrap();
    let _ma_i32: WasmMemoryLimit = 1i32.try_into().unwrap();
    let _ma_i64: WasmMemoryLimit = 1i64.try_into().unwrap();

    let ma = WasmMemoryLimit(100);
    let _ma_ma: WasmMemoryLimit = WasmMemoryLimit::try_from(ma).unwrap();

    assert!(matches!(
        WasmMemoryLimit::try_from(-4).unwrap_err(),
        WasmMemoryLimitError::InvalidMemoryLimit(-4)
    ));

    assert!(matches!(
        WasmMemoryLimit::try_from(562_949_953_421_312_u64).unwrap_err(),
        WasmMemoryLimitError::InvalidMemoryLimit(562_949_953_421_312)
    ));
}
