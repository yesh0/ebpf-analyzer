//! This crate wraps up `AtomicU32` and `AtomicU64` with a trait
//!
//! `AtomicU32` and `AtomicU64` are not available on all platforms.
//! We avoid compile errors by putting them behind an `Option` with selectable features.
//!
//! Also, by separating things into this crate, the unstable feature `atomic_from_mut` is restricted.

#![no_std]
#![feature(atomic_from_mut)]

use core::{num::Wrapping, sync::atomic::Ordering};

pub enum AtomicError {
    IllegalAccess,
    UnsupportedBitness,
}

/// A trait wrapping up `AtomicU32` and `AtomicU64`, which might not be available
pub trait Atomic
where
    Self: Sized,
{
    fn fetch_add(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    fn fetch_or(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    fn fetch_and(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    fn fetch_xor(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    fn swap(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    fn compare_exchange(&self, offset: i16, expected: &Self, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
}

#[cfg(feature = "atomic32")]
pub mod u32 {
    use core::sync::atomic::AtomicU32;

    /// Creates [AtomicU32] from a raw pointer
    /// 
    /// # Safety
    /// It is a wrapper around `AtomicU32::from_mut`.
    pub unsafe fn from_u32_addr(addr: u64) -> &'static mut AtomicU32 {
        AtomicU32::from_mut(&mut *(addr as *mut u32))
    }
}

#[cfg(feature = "atomic64")]
pub mod u64 {
    use core::sync::atomic::AtomicU64;

    /// Creates [AtomicU64] from a raw pointer
    /// 
    /// # Safety
    /// It is a wrapper around `AtomicU64::from_mut`.
    pub unsafe fn from_u64_addr(addr: u64) -> &'static mut AtomicU64 {
        AtomicU64::from_mut(&mut *(addr as *mut u64))
    }
}

fn unchecked_add(x: u64, y: i16) -> u64 {
    x.wrapping_add_signed(y as i64)
}

macro_rules! atomic_impl {
    ( $func_name:ident ) => {
        fn $func_name(&self, offset: i16, rhs: &Self, size: usize) -> Result<u64, AtomicError> {
            let ptr = unchecked_add(*self, offset);
            match size {
                #[cfg(feature = "atomic32")]
                32 => Ok(
                    unsafe { crate::u32::from_u32_addr(ptr) }
                        .$func_name(*rhs as u32, Ordering::SeqCst) as u64,
                ),
                #[cfg(feature = "atomic64")]
                64 => Ok(
                    unsafe { crate::u64::from_u64_addr(ptr) }.$func_name(*rhs, Ordering::SeqCst),
                ),
                _ => Err(AtomicError::UnsupportedBitness),
            }
        }
    };
}

impl Atomic for u64 {
    atomic_impl!(fetch_add);
    atomic_impl!(fetch_or);
    atomic_impl!(fetch_and);
    atomic_impl!(fetch_xor);
    atomic_impl!(swap);

    fn compare_exchange(
        &self,
        offset: i16,
        expected: &Self,
        rhs: &Self,
        size: usize,
    ) -> Result<u64, AtomicError> {
        let ptr = unchecked_add(*self, offset);
        match size {
            #[cfg(feature = "atomic32")]
            32 => Ok(
                match unsafe { crate::u32::from_u32_addr(ptr) }.compare_exchange(
                    *expected as u32,
                    *rhs as u32,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(v) => v,
                    Err(v) => v,
                } as u64,
            ),
            #[cfg(feature = "atomic64")]
            64 => Ok(
                match unsafe { crate::u64::from_u64_addr(ptr) }.compare_exchange(
                    *expected,
                    *rhs,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(v) => v,
                    Err(v) => v,
                },
            ),
            _ => Err(AtomicError::UnsupportedBitness),
        }
    }
}

macro_rules! atomic_wrapping_impl {
    ( $func_name:ident ) => {
        fn $func_name(&self, offset: i16, rhs: &Self, size: usize) -> Result<Wrapping<u64>, AtomicError> {
            self.0.$func_name(offset, &rhs.0, size).map(|i| Wrapping(i))
        }
    };
}

impl Atomic for Wrapping<u64> {
    atomic_wrapping_impl!(fetch_add);
    atomic_wrapping_impl!(fetch_or);
    atomic_wrapping_impl!(fetch_and);
    atomic_wrapping_impl!(fetch_xor);
    atomic_wrapping_impl!(swap);

    fn compare_exchange(
        &self,
        offset: i16,
        expected: &Self,
        rhs: &Self,
        size: usize,
    ) -> Result<Wrapping<u64>, AtomicError> {
        self.0
            .compare_exchange(offset, &expected.0, &rhs.0, size)
            .map(Wrapping)
    }
}
