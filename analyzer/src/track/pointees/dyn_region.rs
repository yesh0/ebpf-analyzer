//! A dynamic region

use core::cell::RefCell;

use alloc::rc::Rc;
use num_traits::ToPrimitive;

use crate::{
    branch::id::Id,
    track::{scalar::Scalar, TrackError, TrackedValue},
};

use super::{is_access_in_range, InnerRegion, MemoryRegion, Pointee, SafeClone};

/// A region with a dynamic range
#[derive(Clone, Debug)]
pub struct DynamicRegion {
    id: Id,
    limit: usize,
    /// A user-defined upper-limit for the limit,
    /// preventing some nasty limits like `u64::MAX`, causing an overflow
    upper_limit: usize,
}

impl DynamicRegion {
    /// Creates a region with fixed size (in bytes)
    pub fn new(size: usize) -> Self {
        Self { id: 0, limit: size, upper_limit: size }
    }

    /// Sets the size limit of this region
    pub fn set_limit(&mut self, limit: &Scalar) {
        self.limit = self.limit.max(match limit.value64() {
            Some(limit) => limit.to_usize().unwrap_or(0),
            None => 0,
        });
        if self.limit > self.upper_limit {
            self.limit = 0;
        }
    }

    /// Sets an upper limit for the length of the region
    ///
    /// This prevents some malicious code generating nasty limits like `u64::MAX`,
    /// causing an overflow and arbitrary memory access.
    pub fn set_upper_limit(&mut self, upper_limit: usize) {
        self.upper_limit = upper_limit;
    }
}

impl SafeClone for DynamicRegion {
    fn get_id(&self) -> Id {
        self.id
    }

    fn set_id(&mut self, id: Id) {
        self.id = id
    }

    fn safe_clone(&self) -> Pointee {
        Rc::new(RefCell::new(self.clone()))
    }

    fn redirects(&mut self, _mapper: &dyn Fn(Id) -> Option<Pointee>) {}
}

impl MemoryRegion for DynamicRegion {
    fn get(&mut self, offset: &Scalar, size: u8) -> Result<TrackedValue, TrackError> {
        is_access_in_range(offset, size, self.limit)?;
        Ok(Scalar::unknown().into())
    }

    fn set(&mut self, offset: &Scalar, size: u8, value: &TrackedValue) -> Result<(), TrackError> {
        match value {
            TrackedValue::Pointer(_) => Err(TrackError::PointeeNotWritable),
            TrackedValue::Scalar(_) => {
                is_access_in_range(offset, size, self.limit)?;
                Ok(())
            }
        }
    }

    fn inner(&mut self) -> InnerRegion {
        InnerRegion::Dyn(self)
    }
}

impl Default for DynamicRegion {
    fn default() -> Self {
        Self {
            id: Default::default(),
            limit: Default::default(),
            upper_limit: 64 * 1024,
        }
    }
}

#[test]
fn test_dyn_region() {
    use crate::track::{
        pointees::empty_region::EmptyRegion,
        pointer::{Pointer, PointerAttributes},
    };
    let mut region = DynamicRegion::default();
    extern crate std;
    std::dbg!(&region);
    region.set_limit(&Scalar::unknown());
    assert_eq!(0, region.limit);
    assert!(region.get(&Scalar::constant64(0), 8).is_err());
    assert!(region
        .set(&Scalar::constant64(0), 8, &Scalar::unknown().into())
        .is_err());
    region.set_limit(&Scalar::constant64(10));
    assert!(region.get(&Scalar::constant64(0), 8).is_ok());
    assert!(region
        .set(&Scalar::constant64(0), 8, &Scalar::unknown().into())
        .is_ok());
    assert!(region
        .set(
            &Scalar::constant64(0),
            8,
            &Pointer::new(PointerAttributes::NON_NULL, EmptyRegion::instance()).into()
        )
        .is_err());
}
