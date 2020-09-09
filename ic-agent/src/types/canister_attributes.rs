#[derive(Clone, Debug)]
pub enum ComputeAllocationError {
    MustBeAPercentage,
}

impl std::fmt::Display for ComputeAllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ComputeAllocationError::MustBeAPercentage => {
                f.write_str("Must be a percent between 0 and 100.")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum MemoryAllocationError {
    InvalidMemorySize,
}

impl std::fmt::Display for MemoryAllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            MemoryAllocationError::InvalidMemorySize => f.write_str(
                "Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively.",
            ),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ComputeAllocation(pub(crate) u8);

impl std::convert::From<ComputeAllocation> for u8 {
    fn from(compute_allocation: ComputeAllocation) -> Self {
        compute_allocation.0
    }
}

impl std::convert::TryFrom<u64> for ComputeAllocation {
    type Error = ComputeAllocationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > 100 {
            Err(ComputeAllocationError::MustBeAPercentage)
        } else {
            Ok(Self(value as u8))
        }
    }
}

impl std::convert::TryFrom<u8> for ComputeAllocation {
    type Error = ComputeAllocationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 100 {
            Err(ComputeAllocationError::MustBeAPercentage)
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct MemoryAllocation(pub(crate) u64);

impl std::convert::From<MemoryAllocation> for u64 {
    fn from(memory_allocation: MemoryAllocation) -> Self {
        memory_allocation.0
    }
}

impl std::convert::TryFrom<u64> for MemoryAllocation {
    type Error = MemoryAllocationError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > 2u64.pow(48) {
            Err(MemoryAllocationError::InvalidMemorySize)
        } else {
            Ok(Self(value as u64))
        }
    }
}

pub struct CanisterAttributes {
    pub compute_allocation: Option<ComputeAllocation>,
    pub memory_allocation: Option<MemoryAllocation>,
}

impl Default for CanisterAttributes {
    fn default() -> Self {
        CanisterAttributes {
            compute_allocation: None,
            memory_allocation: None,
        }
    }
}
