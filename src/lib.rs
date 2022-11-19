//! An analyzer for eBPF binaries

#![no_std]

#![forbid(missing_docs)]

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