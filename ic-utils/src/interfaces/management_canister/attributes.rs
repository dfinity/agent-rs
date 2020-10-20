use thiserror::Error;

#[derive(Error, Debug)]
pub enum ComputeAllocationError {
    #[error("Must be a percent between 0 and 100.")]
    MustBeAPercentage(),
}

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

#[derive(Error, Debug)]
pub enum MemoryAllocationError {
    #[error("Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively. Got {0}.")]
    InvalidMemorySize(u64),
}

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
