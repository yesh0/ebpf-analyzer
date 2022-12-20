//! A simple resource pointee

use core::cell::RefCell;

use alloc::rc::Rc;

use crate::{branch::id::Id, track::{scalar::Scalar, TrackedValue, TrackError}};

use super::{AnyType, MemoryRegion, SafeClone, Pointee, InnerRegion};

/// A resource with a type
#[derive(Clone, Debug)]
pub struct SimpleResource {
    id: Id,
    type_id: AnyType,
}

impl SimpleResource {
    /// Creates an instance
    pub fn new(type_id: AnyType) -> Self {
        Self { id: 0, type_id }
    }
}

impl MemoryRegion for SimpleResource {
    fn get(&mut self, _offset: &Scalar, _size: u8) -> Result<TrackedValue, TrackError> {
        Err(crate::track::TrackError::PointeeNotReadable)
    }

    fn set(&mut self, _offset: &Scalar, _size: u8, _value: &TrackedValue) -> Result<(), TrackError> {
        Err(crate::track::TrackError::PointeeNotWritable)
    }

    fn inner(&mut self) -> InnerRegion {
        InnerRegion::Any((self.type_id, self))
    }
}

impl SafeClone for SimpleResource {
    fn get_id(&self) -> Id {
        self.id
    }

    fn set_id(&mut self, id: Id) {
        self.id = id
    }

    fn safe_clone(&self) -> Pointee {
        Rc::new(RefCell::new(self.clone()))
    }

    fn redirects(&mut self, _mapper: &dyn Fn(Id) -> Option<Pointee>) {
        // nothing to do
    }
}