//! Compiles an eBPF program

#![no_std]
#![cfg_attr(feature = "nightly", feature(mixed_integer_ops))]
#![forbid(missing_docs)]

pub mod compiler;
mod module;

extern crate alloc;
