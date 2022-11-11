use core::cell::RefCell;

use alloc::rc::Rc;

use crate::track::{scalar::Scalar, TrackedValue, TrackError, pointer::Pointee};

use super::PointedValue;

/// Not a valid region
///
/// Operations on this region are forbidden.
/// One may use this struct to represent map pointers or resource descriptors.
pub struct EmptyRegion;

impl EmptyRegion {
    pub fn instance() -> Pointee {
        Rc::new(RefCell::new(EmptyRegion{}))
    }
}

impl PointedValue for EmptyRegion {
    fn get(&mut self, _offset: &Scalar, _size: u8) -> Result<TrackedValue, TrackError> {
        Err(crate::track::TrackError::PointeeNotReadable)
    }

    fn set(&mut self, _offset: &Scalar, _size: u8, _value: &TrackedValue) -> Option<TrackError> {
        Some(crate::track::TrackError::PointeeNotWritable)
    }
}
