//! An analyzer for eBPF binaries

#![no_std]

extern crate alloc;

extern crate ebpf_consts;

extern crate ebpf_atomic;

pub mod blocks;
pub mod analyzer;
pub mod spec;
pub mod vm;