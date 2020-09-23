use thiserror::Error;

#[derive(Error, Debug)]
pub enum ComputeAllocationError {
    #[error("Must be a percent between 0 and 100.")]
    MustBeAPercentage(),
}

#[derive(Error, Debug)]
pub enum MemoryAllocationError {
    #[error("Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively.")]
    InvalidMemorySize(),
}

#[derive(Copy, Clone, Debug)]
pub struct ComputeAllocation(u8);

impl std::convert::From<ComputeAllocation> for u8 {
    fn from(compute_allocation: ComputeAllocation) -> Self {
        compute_allocation.0
    }
}

impl std::convert::TryFrom<u64> for ComputeAllocation {
    type Error = ComputeAllocationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > 100 {
            Err(ComputeAllocationError::MustBeAPercentage())
        } else {
            Ok(Self(value as u8))
        }
    }
}

impl std::convert::TryFrom<u8> for ComputeAllocation {
    type Error = ComputeAllocationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 100 {
            Err(ComputeAllocationError::MustBeAPercentage())
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct MemoryAllocation(u64);

impl std::convert::From<MemoryAllocation> for u64 {
    fn from(memory_allocation: MemoryAllocation) -> Self {
        memory_allocation.0
    }
}

impl std::convert::TryFrom<u64> for MemoryAllocation {
    type Error = MemoryAllocationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > (1u64 << 48) {
            Err(MemoryAllocationError::InvalidMemorySize())
        } else {
            Ok(Self(value as u64))
        }
    }
}
