//! An analyzer for eBPF binaries

#![no_std]

// This has been stablized. We just need to wait a little bit longer for a new Rust release (1.66.0)
#![feature(mixed_integer_ops)]

extern crate alloc;

extern crate ebpf_consts;

extern crate ebpf_atomic;

pub mod blocks;
pub mod analyzer;
pub mod spec;
pub mod interpreter;
pub mod track;
pub mod branch;
pub(crate) mod safe;