// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// Modified from: https://github.com/qmonnet/rbpf/blob/master/src/ebpf.rs

//! This module contains mostly eBPF constants, and some functions permitting to
//! manipulate eBPF instructions.
//!
//! The number of bytes in an instruction, the maximum number of instructions in a program, and
//! also all operation codes are defined here as constants.
//!
//! To learn more about these instructions, I recommend reading the kernel source directly:
//! [kernel/bpf/core.c](https://github.com/torvalds/linux/blob/master/kernel/bpf/core.c).   

#![no_std]

pub type CodeUnit = u64;

/// Stack for the eBPF stack, in slots.
pub const STACK_SIZE: usize = 512;

/// Writable register count, that is, R0, ..., R9
pub const WRITABLE_REGISTER_COUNT: u8 = 10;
/// Readable register count, that is, R0, ..., R10
pub const READABLE_REGISTER_COUNT: u8 = 11;

// eBPF op codes.
// See also https://www.kernel.org/doc/Documentation/networking/filter.txt

// Three least significant bits are operation class:
/// BPF operation class: load from immediate.
pub const BPF_LD    : u8 = 0x00;
/// BPF operation class: load into register.
pub const BPF_LDX   : u8 = 0x01;
/// BPF operation class: store immediate.
pub const BPF_ST    : u8 = 0x02;
/// BPF operation class: store value from register.
pub const BPF_STX   : u8 = 0x03;
/// BPF operation class: 32-bit arithmetic operation.
pub const BPF_ALU   : u8 = 0x04;
/// BPF operation class: jump.
pub const BPF_JMP   : u8 = 0x05;
/// BPF operation class: jump with 32-bit operants
pub const BPF_JMP32 : u8 = 0x06;
/// BPF operation class: 64-bit arithmetic operation.
pub const BPF_ALU64 : u8 = 0x07;

// For load and store instructions:
// +------------+--------+------------+
// |   3 bits   | 2 bits |   3 bits   |
// |    mode    |  size  | insn class |
// +------------+--------+------------+
// (MSB)                          (LSB)

// Size modifiers:
/// BPF size modifier: word (4 bytes).
pub const BPF_W     : u8 = 0x00;
/// BPF size modifier: half-word (2 bytes).
pub const BPF_H     : u8 = 0x08;
/// BPF size modifier: byte (1 byte).
pub const BPF_B     : u8 = 0x10;
/// BPF size modifier: double word (8 bytes).
pub const BPF_DW    : u8 = 0x18;

// Mode modifiers:
/// BPF mode modifier: immediate value.
pub const BPF_IMM     : u8 = 0x00;
/// BPF mode modifier: absolute load (legacy).
pub const BPF_ABS     : u8 = 0x20;
/// BPF mode modifier: indirect load (legacy).
pub const BPF_IND     : u8 = 0x40;
/// BPF mode modifier: load from / store to memory.
pub const BPF_MEM     : u8 = 0x60;
// [ 0x80 reserved ]
// [ 0xa0 reserved ]
/// BPF mode modifier: exclusive add.
pub const BPF_ATOMIC  : u8 = 0xc0;

// For arithmetic (BPF_ALU/BPF_ALU64) and jump (BPF_JMP) instructions:
// +----------------+--------+--------+
// |     4 bits     |1 b.|   3 bits   |
// | operation code | src| insn class |
// +----------------+----+------------+
// (MSB)                          (LSB)

// Source modifiers:
/// BPF source operand modifier: 32-bit immediate value.
pub const BPF_K     : u8 = 0x00;
/// BPF source operand modifier: `src` register.
pub const BPF_X     : u8 = 0x08;
/// BPF byte swap modifier: from host byte order to LE
pub const BPF_TO_LE : u8 = 0x00;
/// BPF byte swap modifier: from host byte order to BE
pub const BPF_TO_BE : u8 = 0x08;
/// BPF byte swap modifier: from host byte order to LE
pub const BPF_FROM_LE : u8 = BPF_TO_LE;
/// BPF byte swap modifier: from host byte order to BE
pub const BPF_FROM_BE : u8 = BPF_TO_BE;

// Operation codes -- BPF_ALU or BPF_ALU64 classes:
/// BPF ALU/ALU64 operation code: addition.
pub const BPF_ADD   : u8 = 0x00;
/// BPF ALU/ALU64 operation code: subtraction.
pub const BPF_SUB   : u8 = 0x10;
/// BPF ALU/ALU64 operation code: multiplication.
pub const BPF_MUL   : u8 = 0x20;
/// BPF ALU/ALU64 operation code: division.
pub const BPF_DIV   : u8 = 0x30;
/// BPF ALU/ALU64 operation code: or.
pub const BPF_OR    : u8 = 0x40;
/// BPF ALU/ALU64 operation code: and.
pub const BPF_AND   : u8 = 0x50;
/// BPF ALU/ALU64 operation code: left shift.
pub const BPF_LSH   : u8 = 0x60;
/// BPF ALU/ALU64 operation code: right shift.
pub const BPF_RSH   : u8 = 0x70;
/// BPF ALU/ALU64 operation code: negation.
pub const BPF_NEG   : u8 = 0x80;
/// BPF ALU/ALU64 operation code: modulus.
pub const BPF_MOD   : u8 = 0x90;
/// BPF ALU/ALU64 operation code: exclusive or.
pub const BPF_XOR   : u8 = 0xa0;
/// BPF ALU/ALU64 operation code: move.
pub const BPF_MOV   : u8 = 0xb0;
/// BPF ALU/ALU64 operation code: sign extending right shift.
pub const BPF_ARSH  : u8 = 0xc0;
/// BPF ALU/ALU64 operation code: endianness conversion.
pub const BPF_END   : u8 = 0xd0;

// Operation codes -- BPF_JMP class:
/// BPF JMP operation code: jump.
pub const BPF_JA    : u8 = 0x00;
/// BPF JMP operation code: jump if equal.
pub const BPF_JEQ   : u8 = 0x10;
/// BPF JMP operation code: jump if greater than.
pub const BPF_JGT   : u8 = 0x20;
/// BPF JMP operation code: jump if greater or equal.
pub const BPF_JGE   : u8 = 0x30;
/// BPF JMP operation code: jump if `src` & `reg`.
pub const BPF_JSET  : u8 = 0x40;
/// BPF JMP operation code: jump if not equal.
pub const BPF_JNE   : u8 = 0x50;
/// BPF JMP operation code: jump if greater than (signed).
pub const BPF_JSGT  : u8 = 0x60;
/// BPF JMP operation code: jump if greater or equal (signed).
pub const BPF_JSGE  : u8 = 0x70;
/// BPF JMP operation code: helper function call.
pub const BPF_CALL  : u8 = 0x80;
/// BPF JMP operation code: return from program.
pub const BPF_EXIT  : u8 = 0x90;
/// BPF JMP operation code: jump if lower than.
pub const BPF_JLT   : u8 = 0xa0;
/// BPF JMP operation code: jump if lower or equal.
pub const BPF_JLE   : u8 = 0xb0;
/// BPF JMP operation code: jump if lower than (signed).
pub const BPF_JSLT  : u8 = 0xc0;
/// BPF JMP operation code: jump if lower or equal (signed).
pub const BPF_JSLE  : u8 = 0xd0;

/// BPF opcode: `call imm` /// helper function call to helper with key `imm`.
pub const CALL       : u8 = BPF_JMP   | BPF_CALL;
/// BPF opcode: tail call.
pub const TAIL_CALL  : u8 = BPF_JMP   | BPF_X | BPF_CALL;
/// BPF opcode: `exit` /// `return r0`.
pub const EXIT       : u8 = BPF_JMP   | BPF_EXIT;

// Operation codes -- extra for BPF_STX class

/// BPF STX ATMOIC immediate code modifier: return the old value
pub const BPF_ATOMIC_FETCH    : i32 = 0x01;
/// BPF STX ATMOIC immediate code: atomic add
pub const BPF_ATOMIC_ADD      : i32 = BPF_ADD as i32;
/// BPF STX ATMOIC immediate code: atomic or
pub const BPF_ATOMIC_OR       : i32 = BPF_OR as i32;
/// BPF STX ATMOIC immediate code: atomic and
pub const BPF_ATOMIC_AND      : i32 = BPF_AND as i32;
/// BPF STX ATMOIC immediate code: atomic xor
pub const BPF_ATOMIC_XOR      : i32 = BPF_XOR as i32;
/// BPF STX ATMOIC immediate code: atomic exchange
pub const BPF_ATOMIC_XCHG     : i32 = 0xe0 | BPF_ATOMIC_FETCH;
/// BPF STX ATMOIC immediate code: atomic compare and swap
pub const BPF_ATOMIC_CMPXCHG  : i32 = 0xf0 | BPF_ATOMIC_FETCH;

pub mod mask {
    use crate::*;

    /// Opcode mask
    pub const BPF_OPCODE_MASK           : u64 = 0xFF;
    /// Opcode mask
    pub const BPF_OPCODE_CLASS_MASK     : u8 = 0b00000111;
    /// Store / load modifiers
    pub const BPF_OPCODE_MODIFIER_MASK  : u8 = 0b11100000;
    /// Store / load operant size
    pub const BPF_OPCODE_SIZE_MASK      : u8 = 0b00011000;
    /// JMP / JMP32 type mask
    pub const BPF_OPCODE_JMP_MASK       : u8 = 0b11110000;
    /// ALU / ALU64 type mask
    pub const BPF_OPCODE_ALU_MASK       : u8 = BPF_OPCODE_JMP_MASK;
    /// JMP / ALU source mask
    pub const BPF_OPCODE_SRC_MASK       : u8 = 0b00001000;

    pub fn is_store_or_load(opcode: u8) -> bool {
        (opcode & 0b00000100) == 0
    }

    pub fn is_jump(opcode: u8) -> bool {
        let class = opcode & BPF_OPCODE_CLASS_MASK;
        class == BPF_JMP || class == BPF_JMP32
    }
}
