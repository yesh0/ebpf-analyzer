//! An analyzer for eBPF binaries

#![no_std]

extern crate alloc;

extern crate ebpf_consts;

pub mod blocks;
pub mod analyzer;
pub mod spec;