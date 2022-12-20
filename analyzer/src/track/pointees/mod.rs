//! This module contains implementations to keep track of memory structures.

use core::{cell::RefCell, fmt::Debug, any::Any};

use alloc::rc::Rc;

use crate::branch::id::Id;

use self::dyn_region::DynamicRegion;

use super::{TrackError, scalar::Scalar, TrackedValue};

pub mod stack_region;
pub mod struct_region;
pub mod empty_region;
pub mod dyn_region;
pub mod simple_resource;
pub mod map_resource;

/// Type id for user-defined types
///
/// Negative ids or a zero one are reserved for internal types.
/// For users of this library, please use a positive id.
pub type AnyType = i32;

/// How we get a concrete reference from `dyn` references
pub enum InnerRegion<'a> {
    /// A dynamic range
    Dyn(&'a mut DynamicRegion),
    /// Anything, allowing for user-defined types
    Any((AnyType, &'a mut dyn Any)),
    /// Not supposed to be used as anything
    None,
}

/// This trait is used in branching, when the VM state is copied into two
///
/// See the VM state implementation [crate::branch::vm::BranchState] for more details.
pub trait SafeClone {
    /// Gets the unique id for this region
    fn get_id(&self) -> Id;
    /// Sets a unique id, used by the VM to track regions
    fn set_id(&mut self, id: Id);
    /// Clones, without redirecting inner pointers if any
    fn safe_clone(&self) -> Pointee;
    /// Redirects some inner pointers
    fn redirects(&mut self, mapper: &dyn Fn(Id) -> Option<Pointee>);
}

/// A memory region that checks memory access
pub trait MemoryRegion: SafeClone + Debug {
    /// Tries to read from the region
    ///
    ///  - `size`: in bytes
    fn get(&mut self, offset: &Scalar, size: u8) -> Result<TrackedValue, TrackError>;
    /// Gets a range of bytes
    fn get_all(&mut self, offset: usize, len: usize) -> Result<(), TrackError> {
        if let Some(end) = offset.checked_add(len) {
            for i in offset..end {
                self.get(&Scalar::constant64(i as u64), 1)?;
            }
            Ok(())
        } else {
            Err(TrackError::PointerOutOfBound)
        }
    }
    /// Tries to write to the region
    ///
    ///  - `size`: in bytes
    fn set(&mut self, offset: &Scalar, size: u8, value: &TrackedValue) -> Result<(), TrackError>;
    /// Sets a range of bytes
    fn set_all(&mut self, offset: usize, len: usize) -> Result<(), TrackError> {
        if let Some(end) = offset.checked_add(len) {
            for i in offset..end {
                self.set(&Scalar::constant64(i as u64), 1, &Scalar::unknown().into())?;
            }
            Ok(())
        } else {
            Err(TrackError::PointerOutOfBound)
        }
    }
    /// Returns a concrete reference to the type behind a `dyn` reference
    fn inner(&mut self) -> InnerRegion {
        InnerRegion::None
    }
}

/// Reference to a memory region
pub type Pointee = Rc<RefCell<dyn MemoryRegion>>;

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

/// Wraps something into [Pointee]
pub fn pointed<T: MemoryRegion + 'static>(region: T) -> Pointee {
    Rc::new(RefCell::new(region))
}
