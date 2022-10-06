//! An analyzer for eBPF binaries

#![no_std]

extern crate alloc;
#[macro_use]
extern crate num_derive;

pub mod blocks;
pub mod analyzer;
pub mod spec;