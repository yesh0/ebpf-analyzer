use core::cell::RefCell;

use alloc::rc::Rc;

use crate::track::{scalar::Scalar, TrackedValue, TrackError};

use super::{MemoryRegion, SafeClone, Pointee};

/// Not a valid region
///
/// Operations on this region are forbidden.
/// One may use this struct to represent map pointers or resource descriptors.
#[derive(Clone)]
pub struct EmptyRegion(usize);

impl EmptyRegion {
    pub fn instance() -> Pointee {
        Rc::new(RefCell::new(EmptyRegion(0)))
    }
}

impl MemoryRegion for EmptyRegion {
    fn get(&mut self, _offset: &Scalar, _size: u8) -> Result<TrackedValue, TrackError> {
        Err(crate::track::TrackError::PointeeNotReadable)
    }

    fn set(&mut self, _offset: &Scalar, _size: u8, _value: &TrackedValue) -> Result<(), TrackError> {
        Err(crate::track::TrackError::PointeeNotWritable)
    }
}

impl SafeClone for EmptyRegion {
    fn get_id(&self) -> usize {
        self.0
    }

    fn set_id(&mut self, id: usize) {
        self.0 = id
    }

    fn safe_clone(&self) -> Pointee {
        Rc::new(RefCell::new(self.clone()))
    }

    fn redirects(&mut self, _mapper: &dyn Fn(usize) -> Pointee) {
        // nothing to do
    }
}
