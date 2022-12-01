//! This file defines some traits used by the VM and the interpreter
//!
//! The main trait is [VmValue],
//! which should represent the available value manipulation operations in eBPF spec.
//!
//! An implementation for [Wrapping<u64>] is provided.

use core::ops::*;
use core::num::Wrapping;

use ebpf_atomic::Atomic;

/// Representing casting between integer types
///
/// It only handles truncation.
pub trait Castable {
    /// Clones the lower half of the values
    fn lower_half(&self) -> Self;
    /// Signifies that the VM only needs the lower half of the value
    fn lower_half_assign(&mut self);
    /// Zeroes the upper half of self while keeping the lower half
    fn zero_upper_half_assign(&mut self);
}

impl Castable for u64 {
    fn lower_half(&self) -> Self {
        *self & 0xFFFF_FFFF
    }

    fn lower_half_assign(&mut self) {
        *self = self.lower_half();
    }

    fn zero_upper_half_assign(&mut self) {
        *self &= 0xFFFF_FFFF
    }
}

impl Castable for Wrapping<u64> {
    fn lower_half(&self) -> Self {
        Self(self.0.lower_half())
    }

    fn lower_half_assign(&mut self) {
        self.0.lower_half_assign()
    }

    fn zero_upper_half_assign(&mut self) {
        self.0.zero_upper_half_assign()
    }
}

/// Used to validate a value
pub trait Verifiable {
    /// Returns `false` if the value is ever invalidated
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
pub trait ShiftAssign<Rhs = Self> {
    /// Sign extending right shift
    ///
    /// The bit `width` is either `32` or `64`.
    fn signed_shr(&mut self, rhs: Rhs, width: u8);
    /// Unsigned right shift
    ///
    /// The bit `width` is either `32` or `64`.
    fn r_shift(&mut self, rhs: Rhs, width: u8);
    /// Left shift
    ///
    /// The bit `width` is either `32` or `64`.
    fn l_shift(&mut self, rhs: Rhs, width: u8);
}

impl ShiftAssign<&u64> for u64 {
    fn signed_shr(&mut self, rhs: &Self, width: u8) {
        if width == 32 {
            *self = ((*self as i32) >> (rhs & 31)) as u32 as u64
        } else {
            *self = ((*self as i64) >> (rhs & 63)) as u64
        }
    }

    fn r_shift(&mut self, rhs: &Self, width: u8) {
        if width == 32 {
            *self = ((*self as u32) >> (rhs & 31)) as u64
        } else {
            *self >>= rhs & 63
        }
    }

    fn l_shift(&mut self, rhs: &Self, width: u8) {
        if width == 32 {
            *self = ((*self as u32) << (rhs & 31)) as u64
        } else {
            *self <<= rhs & 63
        }
    }
}

impl ShiftAssign<&Wrapping<u64>> for Wrapping<u64> {
    fn signed_shr(&mut self, rhs: &Self, width: u8) {
        self.0.signed_shr(&rhs.0, width)
    }

    fn r_shift(&mut self, rhs: &Self, width: u8) {
        self.0.r_shift(&rhs.0, width)
    }

    fn l_shift(&mut self, rhs: &Self, width: u8) {
        self.0.l_shift(&rhs.0, width)
    }
}

/// `Neg` trait for unsigned types, since we have no way to track the sign for `u64`
pub trait NegAssign {
    /// Self-assigns its negated value
    fn neg_assign(&mut self);
}

impl NegAssign for u64 {
    fn neg_assign(&mut self) {
        *self = (-(*self as i64)) as u64
    }
}

impl NegAssign for Wrapping<u64> {
    fn neg_assign(&mut self) {
        *self = Wrapping((-(self.0 as i64)) as u64)
    }
}

/// Implements the BPF_END operation
pub trait ByteSwap {
    /// Swaps the bytes from host endianness to little endian
    ///
    /// Upper bits, if unused, are zeroed.
    fn host_to_le(&mut self, width: i32);
    /// Swaps the bytes from host endianness to big endian
    ///
    /// Upper bits, if unused, are zeroed.
    fn host_to_be(&mut self, width: i32);
}

impl ByteSwap for u64 {
    fn host_to_le(&mut self, width: i32) {
        match width {
            64 => *self = self.to_le(),
            32 => {
                *self = (*self as u32).to_le() as u64
            }
            16 => {
                *self = (*self as u16).to_le() as u64
            }
            _ => *self = 0,
        }
    }

    fn host_to_be(&mut self, width: i32) {
        match width {
            64 => *self = self.to_be(),
            32 => {
                *self = (*self as u32).to_be() as u64
            }
            16 => {
                *self = (*self as u16).to_be() as u64
            }
            _ => *self = 0,
        }
    }
}

impl ByteSwap for Wrapping<u64> {
    fn host_to_le(&mut self, width: i32) {
        self.0.host_to_le(width)
    }

    fn host_to_be(&mut self, width: i32) {
        self.0.host_to_be(width)
    }
}

/// Treats the value as a pointer and provides access to the pointed structures
pub trait Dereference
where
    Self: Sized,
{
    /// Tries to dereference the pointer
    ///
    /// - `size`: in bytes
    ///
    /// # Safety
    /// It is only unsafe for interpreters.
    /// The verifier does not operate on raw pointers.
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self>;
    /// Tries to assign a value to the pointer
    ///
    /// - `size`: in bytes
    ///
    /// # Safety
    /// It is only unsafe for interpreters.
    /// The verifier does not operate on raw pointers.
    unsafe fn set_at(&self, offset: i16, size: usize, value: &Self) -> bool;
}

fn unchecked_add(x: u64, y: i16) -> u64 {
    x.wrapping_add_signed(y as i64)
}

impl Dereference for u64 {
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self> {
        let ptr = unchecked_add(*self, offset);
        Some(match size {
            1 => *(ptr as *const u8) as u64,
            2 => *(ptr as *const u16) as u64,
            4 => *(ptr as *const u32) as u64,
            8 => *(ptr as *const u64),
            _ => 0,
        })
    }

    unsafe fn set_at(&self, offset: i16, size: usize, value: &Self) -> bool {
        let ptr = unchecked_add(*self, offset);
        match size {
            1 => *(ptr as *mut u8) = *value as u8,
            2 => *(ptr as *mut u16) = *value as u16,
            4 => *(ptr as *mut u32) = *value as u32,
            8 => *(ptr as *mut u64) = *value,
            _ => return false,
        }
        true
    }
}

impl Dereference for Wrapping<u64> {
    unsafe fn get_at(&self, offset: i16, size: usize) -> Option<Self> {
        self.0.get_at(offset, size).map(Wrapping)
    }

    unsafe fn set_at(&self, offset: i16, size: usize, value: &Self) -> bool {
        self.0.set_at(offset, size, &value.0)
    }
}

/// Scalar operations
pub trait VmScalar:
    // Type conversion
    Castable
    // Binary ALU operators: Algebraic
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + for<'a> DivAssign<&'a Self>
    + for<'a> RemAssign<&'a Self>
    // Binary ALU operators: Bitwise
    + for<'a> BitAndAssign<&'a Self>
    + for<'a> BitOrAssign<&'a Self>
    + for<'a> BitXorAssign<&'a Self>
    + for<'a> ShiftAssign<&'a Self>
    // Unary ALU operators
    + NegAssign
    + ByteSwap
    // Primitive-like
    + Sized + Clone + Default {
    /// Creates a numberical value from `u32`, zero extending
    fn constantu32(value: u32) -> Self;
    /// Creates a numberical value from `i32`, sign extending
    fn constanti32(value: i32) -> Self;
    /// Creates a numberical value from `u64`
    fn constant64(value: u64) -> Self;
}

/// A value in the VM, compatible with `u64` but allowing injecting custom types
pub trait VmValue:
    VmScalar
    // Value state tracking
    + Verifiable
    // Pointer logic
    + Dereference
    + Atomic
{
}

impl VmScalar for u64 {
    fn constanti32(value: i32) -> Self {
        (value as i64) as u64
    }

    fn constant64(value: u64) -> Self {
        value
    }

    fn constantu32(value: u32) -> Self {
        value as u64
    }
}

impl VmValue for u64 {
}

impl VmScalar for Wrapping<u64> {
    fn constanti32(value: i32) -> Self {
        Wrapping(u64::constanti32(value))
    }

    fn constant64(value: u64) -> Self {
        Wrapping(u64::constant64(value))
    }

    fn constantu32(value: u32) -> Self {
        Wrapping(u64::constantu32(value))
    }
}

impl VmValue for Wrapping<u64> {
}
