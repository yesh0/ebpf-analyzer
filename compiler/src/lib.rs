//! Compiles an eBPF program

// FIXME: Cranelift-codegen is no longer no_std even if it keeps the #![no_std] attr there.
//        We will need to write our own assembler, I'm afraid.
// #![no_std]
#![cfg_attr(feature = "nightly", feature(mixed_integer_ops))]
#![forbid(missing_docs)]

pub mod compiler;
mod module;

extern crate alloc;
