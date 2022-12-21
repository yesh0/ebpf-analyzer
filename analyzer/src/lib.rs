//! An analyzer for eBPF binaries

#![no_std]
#![cfg_attr(feature = "nightly", feature(mixed_integer_ops))]
#![forbid(missing_docs)]

extern crate alloc;

pub mod blocks;
pub mod analyzer;
pub mod spec;
pub mod interpreter;
pub mod track;
pub mod branch;
pub(crate) mod safe;
