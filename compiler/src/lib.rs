//! Compiles an eBPF program

// JITModule requires std.
// We might want to implement our own Module later.
// #![no_std]
#![forbid(missing_docs)]

pub mod compiler;

extern crate alloc;
