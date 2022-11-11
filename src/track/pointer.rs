use core::{
    cell::RefCell,
    ops::{AddAssign, Sub, SubAssign},
};

use alloc::rc::Rc;
use bitflags::bitflags;

use super::{scalar::Scalar, TrackError, TrackedValue, pointees::PointedValue};

bitflags! {
    /// Attributes of the pointer
    ///
    /// Each bit denotes permission to do something, for example:
    /// 1. NON_NULL: maybe some resource descriptor;
    /// 2. NON_NULL | READABLE: const pointer const;
    /// 3. NON_NULL | READABLE | MUTABLE: pointer const;
    /// 4. NON_NULL | READABLE | MUTABLE | ARITHMETIC: pointer.
    pub struct PointerAttributes: u8 {
        /// The pointer is never null
        const NON_NULL   = 0b00000001;
        /// One may dereference this pointer
        const READABLE   = 0b00000010;
        /// The values pointed to allows modification
        const MUTABLE    = 0b00000100;
        /// One may move the pointer around (within the specified bounds)
        /// as well as computing the difference between two pointers (pointing to the same structure)
        const ARITHMETIC = 0b00001000;
        /// This pointer marks the end of a memory region
        const DATA_END   = 0b00010000;
    }
}

/// Reference to a memory region
pub type Pointee = Rc<RefCell<dyn PointedValue>>;

/// A generic pointer, off-loading all the access checking work to [PointedValue].
#[derive(Clone)]
pub struct Pointer {
    attributes: PointerAttributes,
    offset: Scalar,
    pointee: Pointee,
}

impl Pointer {
    pub fn non_null(&self) -> bool {
        self.attributes.contains(PointerAttributes::NON_NULL)
    }
    pub fn is_readable(&self) -> bool {
        self.attributes.contains(PointerAttributes::READABLE)
    }
    pub fn is_mutable(&self) -> bool {
        self.attributes.contains(PointerAttributes::MUTABLE)
    }
    pub fn is_arithmetic(&self) -> bool {
        self.attributes.contains(PointerAttributes::ARITHMETIC)
    }

    pub fn new(attributes: PointerAttributes, pointee: Pointee) -> Pointer {
        Pointer {
            attributes,
            offset: Scalar::constant64(0),
            pointee,
        }
    }

    pub fn get(&mut self, size: u8) -> Result<TrackedValue, TrackError> {
        if self.non_null() {
            if self.is_readable() {
                self.pointee.borrow_mut().get(&self.offset, size)
            } else {
                Err(TrackError::PointeeNotReadable)
            }
        } else {
            Err(TrackError::PointerNullable)
        }
    }

    pub fn set(&mut self, size: u8, value: &TrackedValue) -> Option<TrackError> {
        if self.non_null() {
            if self.is_mutable() {
                self.pointee.borrow_mut().set(&self.offset, size, value)
            } else {
                Some(TrackError::PointeeNotWritable)
            }
        } else {
            Some(TrackError::PointerNullable)
        }
    }

    pub fn is_pointing_to(&self, region: Rc<RefCell<dyn PointedValue>>) -> bool {
        self.pointee.as_ptr() == region.as_ptr()
    }
}

impl AddAssign<&Scalar> for Pointer {
    fn add_assign(&mut self, rhs: &Scalar) {
        self.offset += rhs;
    }
}

impl SubAssign<&Scalar> for Pointer {
    fn sub_assign(&mut self, rhs: &Scalar) {
        self.offset -= rhs;
    }
}

impl Sub<&Self> for &Pointer {
    type Output = Option<Scalar>;

    fn sub(self, rhs: &Self) -> Self::Output {
        if self.non_null() && self.is_arithmetic() && rhs.non_null() && rhs.is_arithmetic() {
            if self.pointee.as_ptr() == rhs.pointee.as_ptr() {
                let mut result = self.offset.clone();
                result -= &rhs.offset;
                return Some(result);
            }
        }
        return None;
    }
}
