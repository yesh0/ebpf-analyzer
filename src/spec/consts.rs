//! BPF Consts
//! 
//! All fields are right shifted to fit the byte boundaries.
//! E.g., `0b11100000` is right shifted into `0b00000111` if it is always masked with `0b11100000`.
//! 
//! Const names may not be identical to those in Linux.

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP64: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

/// Instruction class info stored in the 3 LSB bits
#[derive(FromPrimitive)]
#[repr(u8)]
pub enum InstructionClass {
    /// BPF_LD
    LoadMisc = BPF_LD,
    /// BPF_LDX
    LoadIntoRegister = BPF_LDX,
    /// BPF_ST
    StoreFromImmediate = BPF_ST,
    /// BPF_STX
    StoreFromRegister = BPF_STX,
    /// BPF_ALU
    Arithmetric32 = BPF_ALU,
    /// BPF_JMP
    Jump32 = BPF_JMP,
    /// BPF_JMP64
    Jump64 = BPF_JMP64,
    /// BPF_ALU64
    Arithmetric64 = BPF_ALU64,
}

impl InstructionClass {
    pub fn is_store_or_load(opcode: u8) -> bool {
        (opcode & 0b00000100) == 0
    }

    pub fn is_jump(opcode: u8) -> bool {
        let class = opcode & 0b00000111;
        class == BPF_JMP || class == BPF_JMP64
    }
}

pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x01;
pub const BPF_B: u8 = 0x02;
pub const BPF_DW: u8 = 0x03;

/// Operant size for store / load instructions encoded in `opcode & 0b00011000`
#[derive(FromPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum OperantSize {
    /// BPF_W
    Word = BPF_W,
    /// BPF_H
    HalfWord = BPF_H,
    /// BPF_B
    Byte = BPF_B,
    /// BPF_DW
    DoubleWord = BPF_DW,
}

pub const BPF_MODE_IMM: u8 = 0x00;
pub const BPF_MODE_ABS: u8 = 0x01;
pub const BPF_MODE_IND: u8 = 0x02;
pub const BPF_MODE_MEM: u8 = 0x03;
pub const BPF_MODE_ATOMIC: u8 = 0x06;

pub const BPF_ATOMIC_FETCH: i32 = 0x01;
pub const BPF_ATOMIC_ADD: i32 = 0x00;
pub const BPF_ATOMIC_OR: i32 = 0x40;
pub const BPF_ATOMIC_AND: i32 = 0x50;
pub const BPF_ATOMIC_XOR: i32 = 0xA0;
pub const BPF_ATOMIC_XCHG: i32 = 0xE0 | BPF_ATOMIC_FETCH;
pub const BPF_ATOMIC_CMPXCHG: i32 = 0xF0 | BPF_ATOMIC_FETCH;

/// Byte swap instruction
pub const BPF_ALU_END: u8 = 0x0D;

/// Unconditional jump
pub const BPF_JA: u8 = 0x00;
/// Calls imm
pub const BPF_CALL: u8 = 0x08;
/// Exits
pub const BPF_EXIT: u8 = 0x09;
