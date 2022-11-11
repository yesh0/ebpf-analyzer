use super::{TrackError, scalar::Scalar, TrackedValue};

pub mod stack_region;
pub mod struct_region;
pub mod empty_region;

/// A memory region that checks memory access
pub trait PointedValue {
    fn get(&mut self, offset: &Scalar, size: u8) -> Result<TrackedValue, TrackError>;
    fn set(&mut self, offset: &Scalar, size: u8, value: &TrackedValue) -> Result<(), TrackError>;
}

/// Checks if (offset_start, offset_end + size) is within the limit
///
/// Returns (offset_start, offset_end + size).
fn is_in_range(offset: (i32, i32), size: u8, limit: usize) -> Result<(usize, usize), TrackError> {
    let (min, max) = offset;
    if min <= max {
        if 0 <= min {
            if let Some(end) = (max as u32).checked_add(size as u32) {
                if end as usize <= limit {
                    Ok((min as usize, end as usize))
                } else {
                    Err(TrackError::PointerOutOfBound)
                }
            } else {
                Err(TrackError::PointerOutOfBound)
            }
        } else {
            Err(TrackError::PointerOutOfBound)
        }
    } else {
        Err(TrackError::PointerOffsetMalformed)
    }
}

/// Checks if access using offset to read a value of `size` is within bounds
fn is_access_in_range(
    offset: &Scalar,
    size: u8,
    limit: usize,
) -> Result<(usize, usize), TrackError> {
    if let Some(range) = offset.is_signed_in_sync() {
        is_in_range(range, size, limit)
    } else {
        Err(TrackError::PointerOffsetMalformed)
    }
}
