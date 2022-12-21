//! Compiles an eBPF program

#![no_std]
#![forbid(missing_docs)]

pub mod compiler;
mod module;

extern crate alloc;
