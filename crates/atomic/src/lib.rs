//! This crate wraps up `AtomicU32` and `AtomicU64` with a trait
//!
//! `AtomicU32` and `AtomicU64` are not available on all platforms.
//! We avoid compile errors by putting them behind an `Option` with selectable features.
//!
//! Also, by separating things into this crate, the unstable feature `atomic_from_mut` is restricted.

#![no_std]
#![feature(atomic_from_mut)]
#![cfg_attr(feature = "nightly", feature(mixed_integer_ops))]
#![forbid(missing_docs)]

use core::{num::Wrapping, sync::atomic::Ordering};

/// Error when performing atomic operations
#[derive(Debug)]
pub enum AtomicError {
    /// Invalid memory access
    IllegalAccess,
    /// Unsupported size (currently only 32-bit / 64-bits)
    UnsupportedBitness,
}

/// A trait wrapping up `AtomicU32` and `AtomicU64`, which might not be available
pub trait Atomic
where
    Self: Sized,
{
    /// Wrapper for `fetch_add`
    ///
    /// - `size`: in bytes
    fn fetch_add(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    /// Wrapper for `fetch_or`
    ///
    /// - `size`: in bytes
    fn fetch_or(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    /// Wrapper for `fetch_and`
    ///
    /// - `size`: in bytes
    fn fetch_and(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    /// Wrapper for `fetch_xor`
    ///
    /// - `size`: in bytes
    fn fetch_xor(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    /// Wrapper for `fetch_swap`
    ///
    /// - `size`: in bytes
    fn swap(&self, offset: i16, rhs: &Self, size: usize) -> Result<Self, AtomicError>;
    /// Wrapper for `compare_exchange`
    ///
    /// - `size`: in bytes
    fn compare_exchange(
        &self,
        offset: i16,
        expected: &Self,
        rhs: &Self,
        size: usize,
    ) -> Result<Self, AtomicError>;
}

/// Bridging `AtomicU32`
#[cfg(feature = "atomic32")]
pub mod u32 {
    use core::sync::atomic::AtomicU32;

    /// Creates [AtomicU32] from a raw pointer
    ///
    /// # Safety
    /// It is a wrapper around `AtomicU32::from_mut`.
    pub(super) unsafe fn from_u32_addr(addr: u64) -> &'static mut AtomicU32 {
        AtomicU32::from_mut(&mut *(addr as *mut u32))
    }
}

/// Bridging `AtomicU64`
#[cfg(feature = "atomic64")]
pub mod u64 {
    use core::sync::atomic::AtomicU64;

    /// Creates [AtomicU64] from a raw pointer
    ///
    /// # Safety
    /// It is a wrapper around `AtomicU64::from_mut`.
    pub(super) unsafe fn from_u64_addr(addr: u64) -> &'static mut AtomicU64 {
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
                4 => Ok(unsafe { crate::u32::from_u32_addr(ptr) }
                    .$func_name(*rhs as u32, Ordering::SeqCst) as u64),
                #[cfg(feature = "atomic64")]
                8 => Ok(
                    unsafe { crate::u64::from_u64_addr(ptr) }.$func_name(*rhs, Ordering::SeqCst)
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
            4 => Ok(
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
            8 => Ok(
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
        fn $func_name(
            &self,
            offset: i16,
            rhs: &Self,
            size: usize,
        ) -> Result<Wrapping<u64>, AtomicError> {
            self.0.$func_name(offset, &rhs.0, size).map(Wrapping)
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

#[test]
fn test_memory_access() -> Result<(), AtomicError> {
    let mut i = 0u32;
    let mut j = 0u64;
    let ptr_i = Wrapping(&mut i as *mut u32 as u64);
    let ptr_j = Wrapping(&mut j as *mut u64 as u64);

    assert!(ptr_i.fetch_add(0, &Wrapping(12), 4)? == Wrapping(0));
    assert!(ptr_j.fetch_add(0, &Wrapping(12), 8)? == Wrapping(0));
    assert!(i == 12);
    assert!(j == 12);

    assert!(ptr_i.fetch_and(0, &Wrapping(9), 4)? == Wrapping(12));
    assert!(ptr_j.fetch_and(0, &Wrapping(9), 8)? == Wrapping(12));
    assert!(i == 8);
    assert!(j == 8);

    assert!(ptr_i.fetch_or(0, &Wrapping(16), 4)? == Wrapping(8));
    assert!(ptr_j.fetch_or(0, &Wrapping(16), 8)? == Wrapping(8));
    assert!(i == 24);
    assert!(j == 24);

    assert!(ptr_i.fetch_xor(0, &Wrapping(9), 4)? == Wrapping(24));
    assert!(ptr_j.fetch_xor(0, &Wrapping(9), 8)? == Wrapping(24));
    assert!(i == 17);
    assert!(j == 17);

    assert!(ptr_i.compare_exchange(0, &Wrapping(18), &Wrapping(32), 4)? == Wrapping(17));
    assert!(ptr_j.compare_exchange(0, &Wrapping(18), &Wrapping(32), 8)? == Wrapping(17));
    assert!(ptr_i.compare_exchange(0, &Wrapping(17), &Wrapping(32), 4)? == Wrapping(17));
    assert!(ptr_j.compare_exchange(0, &Wrapping(17), &Wrapping(32), 8)? == Wrapping(17));
    assert!(i == 32);
    assert!(j == 32);

    assert!(ptr_i.fetch_add(0, &Default::default(), 2).is_err());
    assert!(ptr_i.compare_exchange(0, &Default::default(), &Default::default(), 2).is_err());
    assert!(ptr_j.fetch_add(0, &Default::default(), 2).is_err());
    assert!(ptr_j.compare_exchange(0, &Default::default(), &Default::default(), 2).is_err());

    extern crate std;
    std::println!("Tese debug: {:?}", AtomicError::IllegalAccess);

    Ok(())
}
