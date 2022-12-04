//! This module defines a [Pointer] type, keeping offset and permission info about a region.

use core::{
    fmt::Debug,
    ops::{AddAssign, Sub, SubAssign},
};

use bitflags::bitflags;
use num_traits::ToPrimitive;

use crate::branch::id::Id;

use super::{pointees::Pointee, scalar::Scalar, TrackError, TrackedValue};

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

/// A generic pointer, off-loading all the access checking work to [Pointee]
///
/// Essentially, it is [Pointee] plus some [Scalar] offset with some [PointerAttributes].
#[derive(Clone)]
pub struct Pointer {
    attributes: PointerAttributes,
    offset: Scalar,
    pointee: Pointee,
}

impl Pointer {
    /// Creates a non-null, readable, mutable pointer
    pub fn nrw(pointee: Pointee) -> Pointer {
        Self::new(
            PointerAttributes::NON_NULL | PointerAttributes::READABLE | PointerAttributes::MUTABLE,
            pointee,
        )
    }

    /// Creates a non-null, end-marking pointer
    pub fn end(pointee: Pointee) -> Pointer {
        Self::new(
            PointerAttributes::NON_NULL | PointerAttributes::DATA_END,
            pointee,
        )
    }
}

impl Pointer {
    /// Returns `true` if the pointer is never null
    pub fn non_null(&self) -> bool {
        self.attributes.contains(PointerAttributes::NON_NULL)
    }
    /// Sets the pointer as never null
    pub fn set_non_null(&mut self) {
        self.attributes.set(PointerAttributes::NON_NULL, true)
    }
    /// Returns `true` if the memory region pointed to by this pointer is readable
    pub fn is_readable(&self) -> bool {
        self.attributes.contains(PointerAttributes::READABLE)
    }
    /// Returns `true` if the memory region pointed to by this pointer is writable
    pub fn is_mutable(&self) -> bool {
        self.attributes.contains(PointerAttributes::MUTABLE)
    }
    /// Returns `true` if arithmetics on this pointer is allowed
    pub fn is_arithmetic(&self) -> bool {
        self.attributes.contains(PointerAttributes::ARITHMETIC)
    }
    /// Returns `true` if this pointer represents the end of a region
    pub fn is_end_pointer(&self) -> bool {
        self.attributes.contains(PointerAttributes::DATA_END)
    }

    /// Gets the offset
    pub fn offset(&self) -> &Scalar {
        &self.offset
    }

    /// Creates a new pointer
    pub fn new(attributes: PointerAttributes, pointee: Pointee) -> Pointer {
        Pointer {
            attributes,
            offset: Scalar::constant64(0),
            pointee,
        }
    }

    /// Tries to read from the pointed memory
    ///
    /// - `size`: in bytes
    pub fn get(&self, size: u8) -> Result<TrackedValue, TrackError> {
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

    /// Tries to write to the pointed memory
    ///
    /// - `size`: in bytes
    pub fn set(&self, size: u8, value: &TrackedValue) -> Result<(), TrackError> {
        if self.non_null() {
            if self.is_mutable() {
                self.pointee.borrow_mut().set(&self.offset, size, value)
            } else {
                Err(TrackError::PointeeNotWritable)
            }
        } else {
            Err(TrackError::PointerNullable)
        }
    }

    /// Tries to write to the pointed memory
    ///
    /// - `len`: in bytes
    pub fn set_all(&self, len: usize) -> Result<(), TrackError> {
        if self.non_null() {
            if self.is_mutable() {
                if let Some(Some(offset)) = self.offset.value64().map(|i| i.to_usize()) {
                    self.pointee.borrow_mut().set_all(offset, len)
                } else {
                    Err(TrackError::PointerOffsetMalformed)
                }
            } else {
                Err(TrackError::PointeeNotWritable)
            }
        } else {
            Err(TrackError::PointerNullable)
        }
    }

    /// Checks whether this pointer points to a memory region of the same id
    pub fn is_pointing_to(&self, region: Id) -> bool {
        self.get_pointing_to() == region
    }

    /// Gets the memory region id
    pub fn get_pointing_to(&self) -> Id {
        self.pointee.borrow().get_id()
    }

    /// Returns the region
    pub fn get_pointing_region(&self) -> Pointee {
        self.pointee.clone()
    }

    /// Sets the pointer to point to another region
    pub fn redirect(&mut self, region: Pointee) {
        self.pointee = region;
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

impl Sub<Self> for &Pointer {
    type Output = Option<Scalar>;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.non_null()
            && self.is_arithmetic()
            && rhs.non_null()
            && rhs.is_arithmetic()
            && self.get_pointing_to() == rhs.get_pointing_to()
        {
            let mut result = self.offset.clone();
            result -= &rhs.offset;
            return Some(result);
        }
        None
    }
}

impl Debug for Pointer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_end_pointer() {
            f.write_fmt(format_args!("Pointer{{off:end,"))?;
        } else {
            f.write_fmt(format_args!("Pointer{{off:{:?},", &self.offset))?;
        }
        f.write_fmt(format_args!(
            "ptr:0x{:x}}}",
            &if let Ok(region) = self.get_pointing_region().try_borrow() {
                region.get_id() as usize
            } else {
                self.pointee.as_ptr() as *const () as usize
            }
        ))
    }
}
