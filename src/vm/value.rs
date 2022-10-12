//! This file defines some traits used by the VM and the interpreter
//!
//! These traits

use core::{ops::*, num::Wrapping, cmp::Ordering};

use ebpf_atomic::Atomic;

/// Representing casting between integer types
///
/// It only handles truncation.
pub trait Downcast {
    fn cast_u64(self) -> Self;
    fn cast_i64(self) -> Self;
    fn cast_u32(self) -> Self;
    fn cast_i32(self) -> Self;
}

impl Downcast for u64 {
    fn cast_u64(self) -> Self {
        self as u64
    }

    fn cast_i64(self) -> Self {
        self as i64 as u64
    }

    fn cast_u32(self) -> Self {
        self as u32 as u64
    }

    fn cast_i32(self) -> Self {
        self as i32 as u64
    }
}

impl Downcast for Wrapping<u64> {
    fn cast_u64(self) -> Self {
        Wrapping(self.0.cast_u64())
    }

    fn cast_i64(self) -> Self {
        Wrapping(self.0.cast_i64())
    }

    fn cast_u32(self) -> Self {
        Wrapping(self.0.cast_u32())
    }

    fn cast_i32(self) -> Self {
        Wrapping(self.0.cast_i32())
    }
}

/// Used to validate a value
pub trait Verifiable {
    fn is_valid(&self) -> bool;
}

impl Verifiable for u64 {
    fn is_valid(&self) -> bool {
        true
    }
}

impl Verifiable for Wrapping<u64> {
    fn is_valid(&self) -> bool {
        true
    }
}

/// Signed right shift, since we have no way to track the sign for `u64`
pub trait Shift<Rhs = Self> {
    type Output;

    fn signed_shr(self, rhs: Rhs) -> Self::Output;
    fn r_shift(self, rhs: Rhs) -> Self::Output;
    fn l_shift(self, rhs: Rhs) -> Self::Output;
}

impl Shift<u64> for u64 {
    type Output = Self;

    fn signed_shr(self, rhs: Self) -> Self {
        ((self as i64) >> (rhs & 63)) as u64
    }

    fn r_shift(self, rhs: u64) -> Self::Output {
        self >> (rhs & 63)
    }

    fn l_shift(self, rhs: u64) -> Self::Output {
        self << (rhs & 63)
    }
}

impl Shift<Wrapping<u64>> for Wrapping<u64> {
    type Output = Self;

    fn signed_shr(self, rhs: Self) -> Self::Output {
        Wrapping(self.0.signed_shr(rhs.0))
    }

    fn r_shift(self, rhs: Wrapping<u64>) -> Self::Output {
        Wrapping(self.0.r_shift(rhs.0))
    }

    fn l_shift(self, rhs: Wrapping<u64>) -> Self::Output {
        Wrapping(self.0.l_shift(rhs.0))
    }
}

/// `Neg` trait for unsigned types, since we have no way to track the sign for `u64`
pub trait SignedNeg {
    type Output;

    fn signed_neg(self) -> Self::Output;
}

impl SignedNeg for u64 {
    type Output = u64;

    fn signed_neg(self) -> Self::Output {
        (-(self as i64)) as u64
    }
}

impl SignedNeg for Wrapping<u64> {
    type Output = Self;

    fn signed_neg(self) -> Self::Output {
        Wrapping((-(self.0 as i64)) as u64)
    }
}

/// Implements the BPF_END operation
pub trait ByteSwap {
    fn host_to_le(self, width: i32) -> Self;
    fn host_to_be(self, width: i32) -> Self;
}

impl ByteSwap for u64 {
    fn host_to_le(self, width: i32) -> Self {
        match width {
            64 => {
                self.to_le()
            }
            32 => {
                let lower = (self as u32).to_le();
                let upper = ((self >> 32) as u32).to_le();
                ((upper as u64) << 32) | lower as u64
            }
            16 => {
                let mut output = 0u64;
                for i in 0..4 {
                    let n = (((self >> (i * 16)) & 0xFFFF) as u16).to_le();
                    output |= (n as u64) << (i * 8);
                }
                output
            }
            _ => 0,
        }
    }

    fn host_to_be(self, width: i32) -> Self {
        match width {
            64 => {
                self.to_be()
            }
            32 => {
                let lower = (self as u32).to_be();
                let upper = ((self >> 32) as u32).to_be();
                ((upper as u64) << 32) | lower as u64
            }
            16 => {
                let mut output = 0u64;
                for i in 0..4 {
                    let n = (((self >> (i * 16)) & 0xFFFF) as u16).to_be();
                    output |= (n as u64) << (i * 8);
                }
                output
            }
            _ => 0,
        }
    }
}

impl ByteSwap for Wrapping<u64> {
    fn host_to_le(self, width: i32) -> Self {
        Wrapping(self.0.host_to_le(width))
    }

    fn host_to_be(self, width: i32) -> Self {
        Wrapping(self.0.host_to_be(width))
    }
}

/// `PartialOrd` trait for unsigned types, since we have no way to track the sign for `u64`
pub trait SignedPartialOrd {
    fn signed_partial_cmp(&self, other: &Self) -> Option<Ordering>;
}

impl SignedPartialOrd for u64 {
    fn signed_partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (*self as i64).partial_cmp(&(*other as i64))
    }
}

impl SignedPartialOrd for Wrapping<u64> {
    fn signed_partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Treats the value as a pointer and provides access to the pointed structures
pub trait Dereference where Self: Sized {
    /// Tries to dereference the pointer
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self>;
    /// Tries to assign a value to the pointer
    unsafe fn set_at(&self, offset: i16, size: usize, value: Self) -> bool;
}

fn unchecked_add(x: u64, y: i16) -> u64 {
    if y >= 0 {
        x + y as u64
    } else {
        x + (-y) as u64
    }
}

impl Dereference for u64 {
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self> {
        let ptr = unchecked_add(*self, offset);
        Some(match size {
            8 => *(ptr as *const u8) as u64,
            16 => *(ptr as *const u16) as u64,
            32 => *(ptr as *const u32) as u64,
            64 => *(ptr as *const u64) as u64,
            _ => 0
        })
    }

    unsafe fn set_at(&self, offset: i16, size: usize, value: Self) -> bool {
        let ptr = unchecked_add(*self, offset);
        match size {
            8 => *(ptr as *mut u8) = value as u8,
            16 => *(ptr as *mut u16) = value as u16,
            32 => *(ptr as *mut u32) = value as u32,
            64 => *(ptr as *mut u64) = value as u64,
            _ => return false,
        }
        true
    }
}

impl Dereference for Wrapping<u64> {
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self> {
        self.0.get_at(offset, size).map(|i| Wrapping(i))
    }

    unsafe fn set_at(&self, offset: i16, size: usize, value: Self) -> bool {
        self.0.set_at(offset, size, value.0)
    }
}

/// A value in the VM, compatible with `u64` but allowing injecting custom types
pub trait VmValue:
    // Type conversion
    Downcast
    // Binary ALU operators: Algebraic
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + Rem<Self, Output = Self>
    // Binary ALU operators: Bitwise
    + BitAnd<Self, Output = Self>
    + BitOr<Self, Output = Self>
    + BitXor<Self, Output = Self>
    + Shift<Self, Output = Self>
    // Unary ALU operators
    + Not<Output = Self>
    + SignedNeg<Output = Self>
    + ByteSwap
    // Ordering: Using PartialOrd instead of Ord, since one cannot compare pointers with integers
    + PartialOrd<Self>
    + PartialEq<Self>
    + SignedPartialOrd
    // Value state tracking
    + Verifiable
    // Pointer logic
    + Dereference
    + Atomic
    // Primitive-like
    + Sized + Copy + Default
{
    /// Creates a numberical value from `i32`
    fn constant32(value: i32) -> Self;
    /// Creates a numberical value from `u64`
    fn constant64(value: u64) -> Self;
    /// Creates a pointer to the stack
    fn stack_ptr(value: u64) -> Self;
}

impl VmValue for u64 {
    fn constant32(value: i32) -> Self {
        (value as i64) as u64
    }

    fn constant64(value: u64) -> Self {
        value
    }

    fn stack_ptr(value: u64) -> Self {
        value
    }
}

impl VmValue for Wrapping<u64> {
    fn constant32(value: i32) -> Self {
        Wrapping(u64::constant32(value))
    }

    fn constant64(value: u64) -> Self {
        Wrapping(u64::constant64(value))
    }

    fn stack_ptr(value: u64) -> Self {
        Wrapping(value)
    }
}
