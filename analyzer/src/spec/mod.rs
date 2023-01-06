//! This module contains the instruction verification according to the instruction set specification.

pub mod proto;

use core::fmt::Debug;
use core::hint::unreachable_unchecked;

use ebpf_consts::mask::*;
use ebpf_consts::*;

/// Instruction offset
pub type CodeOffset = usize;

/// BPF instruction
///
/// The member functions are intentionally passing by value.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Instruction {
    /// opcode
    pub opcode: u8,
    /// registers (lower four bits: dst_reg, higher four bits: src_reg)
    pub regs: u8,
    /// offset
    pub off: i16,
    /// imm
    pub imm: i32,
}

/// BPF wide instruction
pub struct WideInstruction {
    /// The first 64-bit value
    pub instruction: Instruction,
    /// The following 64-bit value
    ///
    /// No, this is not `imm64`.
    pub imm: u64,
}

/// Parsed instruction result
pub enum ParsedInstruction {
    /// Apparently illegal instruction
    None,
    /// Seemingly a 64-bit instruction
    Instruction(Instruction),
    /// Seemingly a 128-bit instruction
    WideInstruction(WideInstruction),
}

/// Basic jump instruction classification
pub enum JumpInstruction {
    /// An unconditional jump
    Unconditional(i16),
    /// A conditional jump
    Conditional(i16),
    /// Exits
    Exit,
}

/// Illegal instruction according to the spec
#[derive(Debug)]
pub enum IllegalInstruction {
    /// Unrecognized opcode
    IllegalOpCode,
    /// Non-existent / not readable / not writable register
    IllegalRegister,
    /// General error
    IllegalInstruction,
    /// Unsupported legacy instruction
    LegacyInstruction,
    /// Unused fields must be zeroed
    UnusedFieldNotZeroed,
    /// Atomic width other than 32 and 64
    UnsupportedAtomicWidth,
    /// Tries to jump right into an 128-bit instruction
    UnalignedJump,
    /// Jumps out of the whole program
    OutOfBoundJump,
    /// Jumps out of the current function
    OutOfBoundFunction,
    /// Map file descriptor not available (either a non-existent fd or forbidden usage)
    MapFdNotAvailable,
}

impl ParsedInstruction {
    /// Validates the instruction
    pub fn validate(&self) -> Result<(), IllegalInstruction> {
        match self {
            ParsedInstruction::None => Err(IllegalInstruction::IllegalInstruction),
            ParsedInstruction::Instruction(i) => i.validate(),
            ParsedInstruction::WideInstruction(w) => w.validate(),
        }
    }
}

impl WideInstruction {
    /// `insn0.imm`
    pub fn imm0(&self) -> i32 {
        self.instruction.imm
    }

    /// `insn1.imm`
    pub fn imm1(&self) -> i32 {
        (self.imm >> 32) as i32
    }

    /// `insn0.imm | (insn1.imm << 32)`
    pub fn imm64(&self) -> u64 {
        (self.imm0() as u32 as u64) | ((self.imm >> 32) << 32)
    }

    /// Unused part in the second 64 bits
    fn off1(&self) -> i32 {
        self.imm as i32
    }

    /// Validates the instruction
    pub fn validate(&self) -> Result<(), IllegalInstruction> {
        if self.instruction.is_wide() {
            let imm1 = match self.instruction.src_reg() {
                BPF_IMM64_IMM => true,
                BPF_IMM64_MAP_FD | BPF_IMM64_MAP_IDX => false,
                BPF_IMM64_MAP_VALUE | BPF_IMM64_MAP_IDX_VALUE => true,
                BPF_IMM64_BTF_ID => false,
                BPF_IMM64_FUNC => false,
                _ => return Err(IllegalInstruction::IllegalRegister),
            };
            if self.instruction.off == 0 && self.off1() == 0 && (imm1 || self.imm1() == 0) {
                if self.instruction.dst_reg() < WRITABLE_REGISTER_COUNT {
                    Ok(())
                } else {
                    Err(IllegalInstruction::IllegalRegister)
                }
            } else {
                Err(IllegalInstruction::UnusedFieldNotZeroed)
            }
        } else {
            Err(IllegalInstruction::IllegalInstruction)
        }
    }
}

impl Instruction {
    /// Packs fields into a `u64` instruction
    pub fn pack(opcode: u8, src_reg: u8, dst_reg: u8, offset: i16, imm: i32) -> u64 {
        let opcode = opcode as u64;
        let src_reg = src_reg as u64;
        let dst_reg = dst_reg as u64;
        let offset = offset as u16 as u64;
        let imm = imm as u32 as u64;

        opcode | (dst_reg << 8) | (src_reg << (8 + 4)) | (offset << 16) | (imm << 32)
    }

    /// Gets the opcode
    pub fn opcode(code: u64) -> u8 {
        (code & BPF_OPCODE_MASK) as u8
    }

    /// Constructs an instruction from code at `pc`
    ///
    /// It does not check for instruction validity.
    pub fn from(code: &[u64], pc: usize) -> ParsedInstruction {
        let insn = Instruction::from_raw(code[pc]);
        if insn.is_wide() {
            if pc + 1 >= code.len() {
                ParsedInstruction::None
            } else {
                ParsedInstruction::WideInstruction(WideInstruction {
                    instruction: insn,
                    imm: code[pc + 1],
                })
            }
        } else {
            ParsedInstruction::Instruction(insn)
        }
    }

    /// Constructs an instruction from a encoded code
    pub fn from_raw(encoded: u64) -> Instruction {
        Instruction {
            opcode: Self::opcode(encoded),
            regs: ((encoded >> 8) & 0xFF) as u8,
            off: ((encoded >> 16) & 0xFFFF) as i16,
            imm: (encoded >> 32) as i32,
        }
    }

    /// Checks whether an instruction is a valid one
    ///
    /// The following checks are performed:
    /// 1. Legacy instructions (BPF Packet access instructions) are disallowed;
    /// 2. Unused fields must be zeroed;
    /// 3. R10 is read-only while the other ten are writable;
    ///
    /// Note that for wide instructions, ideally, the next instruction
    /// will have its low 32 bits zeroed. But we are not checking that here.
    /// Use [WideInstruction] to check that.
    pub fn validate(self) -> Result<(), IllegalInstruction> {
        match self.opcode & BPF_OPCODE_CLASS_MASK {
            BPF_LD => Err(IllegalInstruction::LegacyInstruction),
            BPF_LDX => self.is_store_load_valid::<true, false>(),
            BPF_ST => self.is_store_load_valid::<false, true>(),
            BPF_STX => {
                if (self.opcode & BPF_OPCODE_MODIFIER_MASK) == BPF_ATOMIC {
                    self.is_atomic_store_valid()
                } else {
                    self.is_store_load_valid::<false, false>()
                }
            }
            BPF_ALU => self.is_arithmetic_valid(),
            BPF_JMP => self.is_jump_valid::<64>(),
            BPF_JMP32 => self.is_jump_valid::<32>(),
            BPF_ALU64 => self.is_arithmetic_valid(),
            _ => unsafe { unreachable_unchecked() },
        }
    }

    /// `src_reg` (upper 4-bits)
    pub fn src_reg(self) -> u8 {
        self.regs >> 4
    }

    /// `dst_reg` (lower 4-bits)
    pub fn dst_reg(self) -> u8 {
        self.regs & 0x0F
    }

    /// Returns `Some(destination)` for jump instructions (other than BPF_CALL)
    ///
    /// See [JumpInstruction].
    pub fn jumps_to(self) -> Option<JumpInstruction> {
        if is_jump(self.opcode) {
            let operation = self.opcode & BPF_OPCODE_JMP_MASK;
            if operation == BPF_JA {
                Some(JumpInstruction::Unconditional(self.off))
            } else if operation == BPF_EXIT {
                Some(JumpInstruction::Exit)
            } else if operation == BPF_CALL {
                None
            } else {
                Some(JumpInstruction::Conditional(self.off))
            }
        } else {
            None
        }
    }

    /// Returns `Some(offset)` if it is a call instruction with [BPF_CALL_PSEUDO]
    pub fn is_pseudo_call(self) -> Option<i32> {
        if self.opcode == BPF_JMP_CALL && self.src_reg() == BPF_CALL_PSEUDO {
            Some(self.imm)
        } else {
            None
        }
    }

    /// Returns `Some(offset)` if it is a wide instruction with [BPF_IMM64_FUNC]
    pub fn is_ldimm64_func(self) -> Option<i32> {
        if self.is_wide() && self.src_reg() == BPF_IMM64_FUNC {
            Some(self.imm)
        } else {
            None
        }
    }

    /// Returns `Some(fd)` if it is a wide instruction with [BPF_IMM64_MAP_FD]
    /// or [BPF_IMM64_MAP_VALUE]
    pub fn is_ldimm64_map_fd(self) -> Option<i32> {
        if self.is_wide()
            && (self.src_reg() == BPF_IMM64_MAP_FD || self.src_reg() == BPF_IMM64_MAP_VALUE)
        {
            Some(self.imm)
        } else {
            None
        }
    }

    /// `true` if this instruction is a wide instruction (i.e. taking 128 bits)
    ///
    /// Currently, there is only one wide instruction.
    pub fn is_wide(self) -> bool {
        self.opcode == (BPF_LD | BPF_DW | BPF_IMM)
    }

    /// Checks a store / load instruction
    ///
    /// - BPF_MEM:
    ///   - BPF_LDX: Requires writable dst_reg, readable src_reg and off;
    ///   - BPF_STX: Requires readable dst_reg, readable src_reg and off;
    ///   - BPF_ST : Requires readable dst_reg, imm and off.
    fn is_store_load_valid<const LOAD: bool, const IMM: bool>(
        self,
    ) -> Result<(), IllegalInstruction> {
        if (self.opcode & BPF_OPCODE_MODIFIER_MASK) != BPF_MEM {
            return Err(IllegalInstruction::IllegalOpCode);
        }

        if LOAD {
            if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                return Err(IllegalInstruction::IllegalRegister);
            }
        } else if self.dst_reg() >= READABLE_REGISTER_COUNT {
            return Err(IllegalInstruction::IllegalRegister);
        }

        if IMM {
            if self.src_reg() != 0 {
                return Err(IllegalInstruction::UnusedFieldNotZeroed);
            }
        } else {
            if self.src_reg() >= READABLE_REGISTER_COUNT {
                return Err(IllegalInstruction::IllegalRegister);
            }
            if self.imm != 0 {
                return Err(IllegalInstruction::UnusedFieldNotZeroed);
            }
        }

        Ok(())
    }

    /// Checks if a jump instruction is valid
    ///
    /// 1. BPF_EXIT does not use any other fields;
    /// 2. BPF_CALL calls the function specified in the immediate number;
    /// 3. BPF_JA jumps to the offset unconditionally;
    /// 4. Other instructions either:
    ///    a) compares dst_reg against the immediate number;
    ///    b) or compares dst_reg against the src_reg.
    fn is_jump_valid<const XLEN: u8>(self) -> Result<(), IllegalInstruction> {
        match self.opcode & BPF_OPCODE_JMP_MASK {
            0xE0 => Err(IllegalInstruction::IllegalOpCode),
            0xF0 => Err(IllegalInstruction::IllegalOpCode),
            BPF_JA => {
                if XLEN == 32 {
                    Err(IllegalInstruction::IllegalInstruction)
                } else if self.regs == 0 && self.imm == 0 {
                    Ok(())
                } else {
                    Err(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            BPF_CALL => {
                // TODO: support pseudo tail call
                if self.dst_reg() == 0 && self.off == 0 {
                    match self.src_reg() {
                        BPF_CALL_HELPER | BPF_CALL_PSEUDO | BPF_CALL_KFUNC => Ok(()),
                        _ => Err(IllegalInstruction::UnusedFieldNotZeroed),
                    }
                } else {
                    Err(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            BPF_EXIT => {
                if XLEN == 32 {
                    Err(IllegalInstruction::IllegalInstruction)
                } else if self.regs == 0 && self.imm == 0 && self.off == 0 {
                    Ok(())
                } else {
                    Err(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            _ => self.is_arithmetic_registers_valid::<false>(),
        }
    }

    /// Checks if a jump instruction is valid
    ///
    /// 1. None of them uses the offset;
    /// 2. All of them writes to the dst_reg;
    /// 3. BPF_ALU_END operates on dst_reg according to the immediate number, requiring BPF_ALU;
    /// 4. BPF_NEG reads and writes to from dst_reg, requiring BPF_K;
    /// 5. Others read from either src_reg or the immediate number.
    fn is_arithmetic_valid(self) -> Result<(), IllegalInstruction> {
        if self.off != 0 {
            return Err(IllegalInstruction::UnusedFieldNotZeroed);
        }

        match self.opcode & BPF_OPCODE_ALU_MASK {
            0xE0 => Err(IllegalInstruction::IllegalOpCode),
            0xF0 => Err(IllegalInstruction::IllegalOpCode),
            BPF_NEG => {
                if self.src_reg() != 0 {
                    Err(IllegalInstruction::UnusedFieldNotZeroed)
                } else if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                    Err(IllegalInstruction::IllegalRegister)
                } else if (self.opcode & BPF_X) != 0 {
                    Err(IllegalInstruction::IllegalOpCode)
                } else {
                    Ok(())
                }
            }
            BPF_END => {
                if (self.opcode & BPF_OPCODE_CLASS_MASK) == BPF_ALU64 {
                    Err(IllegalInstruction::IllegalOpCode)
                } else if self.src_reg() != 0 {
                    Err(IllegalInstruction::UnusedFieldNotZeroed)
                } else if self.dst_reg() < WRITABLE_REGISTER_COUNT {
                    if [16, 32, 64].contains(&self.imm) {
                        Ok(())
                    } else {
                        Err(IllegalInstruction::IllegalInstruction)
                    }
                } else {
                    Err(IllegalInstruction::IllegalRegister)
                }
            }
            _ => self.is_arithmetic_registers_valid::<true>(),
        }
    }

    fn is_arithmetic_source_immediate(self) -> bool {
        (self.opcode & BPF_OPCODE_SRC_MASK) == BPF_K
    }

    fn is_arithmetic_registers_valid<const WRITES_TO_DST: bool>(
        self,
    ) -> Result<(), IllegalInstruction> {
        if WRITES_TO_DST {
            if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                return Err(IllegalInstruction::IllegalRegister);
            }
        } else if self.dst_reg() >= READABLE_REGISTER_COUNT {
            return Err(IllegalInstruction::IllegalRegister);
        }

        if self.is_arithmetic_source_immediate() {
            if self.src_reg() == 0 {
                Ok(())
            } else {
                Err(IllegalInstruction::UnusedFieldNotZeroed)
            }
        } else if self.imm == 0 {
            if self.src_reg() < READABLE_REGISTER_COUNT {
                Ok(())
            } else {
                Err(IllegalInstruction::IllegalRegister)
            }
        } else {
            Err(IllegalInstruction::UnusedFieldNotZeroed)
        }
    }

    /// Checks an atomic instruction
    ///
    /// 1. BPF_XCHG: Exchanges the original value into src_reg;
    /// 2. BPF_CMPXCHG: The value is stored into R0, src_reg not modified.
    /// 3. Other instructions store into src_reg if the BPF_FETCH flag is set.
    fn is_atomic_store_valid(self) -> Result<(), IllegalInstruction> {
        let operant_size: u8 = self.opcode & BPF_OPCODE_SIZE_MASK;
        if !((cfg!(feature = "atomic64") && operant_size == BPF_DW)
            || (cfg!(feature = "atomic32") && operant_size == BPF_W))
        {
            return Err(IllegalInstruction::UnsupportedAtomicWidth);
        }

        if self.dst_reg() >= READABLE_REGISTER_COUNT {
            return Err(IllegalInstruction::IllegalRegister);
        }

        let src_limit = if self.imm == BPF_ATOMIC_CMPXCHG || (self.imm & BPF_ATOMIC_FETCH) == 0 {
            READABLE_REGISTER_COUNT
        } else {
            WRITABLE_REGISTER_COUNT
        };

        if self.src_reg() >= src_limit {
            return Err(IllegalInstruction::IllegalRegister);
        }

        Ok(())
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "( opcode: {:02x}, dst_reg: {:x}, src_reg: {:x}, off: {:04x}, imm: {:08x} )",
            self.opcode,
            self.dst_reg(),
            self.src_reg(),
            self.off,
            self.imm
        ))
    }
}

#[test]
fn test_misc() {
    // Clone test
    let i = Instruction::from_raw(0);
    macro_rules! call_clone {
        ($i:ident) => {
            $i.clone()
        };
    }
    let j = call_clone!(i);
    assert_eq!(
        Instruction::pack(j.opcode, j.src_reg(), j.src_reg(), j.off, j.imm),
        0
    );

    // Debug test
    extern crate std;
    std::dbg!(IllegalInstruction::IllegalInstruction);
}

#[test]
fn test_parsing() {
    let code: &[u64] = &[
        // 64-bit: addition
        (BPF_ALU64 | BPF_ADD | BPF_K) as u64,
        // 128-bit
        (BPF_LD | BPF_DW | BPF_IMM) as u64 | (0xCAFE_BABEu64 << 32),
        (0xDEAD_BEEFu64 << 32),
        // half of 128-bit
        (BPF_LD | BPF_DW | BPF_IMM) as u64,
    ];
    assert!(matches!(
        Instruction::from(code, 0),
        ParsedInstruction::Instruction(_)
    ));
    assert!(matches!(
        Instruction::from(code, 1),
        ParsedInstruction::WideInstruction(_)
    ));
    assert!(matches!(
        Instruction::from(code, 3),
        ParsedInstruction::None
    ));

    match Instruction::from(code, 1) {
        ParsedInstruction::WideInstruction(w) => {
            assert_eq!(w.imm0(), 0xCAFE_BABEu64 as i32);
            assert_eq!(w.imm1(), 0xDEAD_BEEFu64 as i32);
            assert_eq!(w.imm64(), 0xDEAD_BEEF_CAFE_BABE);
        }
        _ => panic!(),
    }
}

#[test]
fn test_wide_validation() {
    let mut w = WideInstruction {
        instruction: Instruction::from_raw(0),
        imm: 0,
    };
    assert!(matches!(
        w.validate(),
        Err(IllegalInstruction::IllegalInstruction)
    ));
    w.instruction.opcode = BPF_LD | BPF_DW | BPF_IMM;
    assert!(w.validate().is_ok());
    let imm1_unused = [
        BPF_IMM64_MAP_FD,
        BPF_IMM64_MAP_IDX,
        BPF_IMM64_BTF_ID,
        BPF_IMM64_FUNC,
    ];
    let imm1_used = [BPF_IMM64_IMM, BPF_IMM64_MAP_VALUE, BPF_IMM64_MAP_IDX_VALUE];
    w.imm = 0x1_0000_0000;
    for src in 0..0b1111 {
        w.instruction.regs = src << 4;
        if imm1_unused.contains(&src) {
            assert!(matches!(
                w.validate(),
                Err(IllegalInstruction::UnusedFieldNotZeroed)
            ));
        } else if imm1_used.contains(&src) {
            assert!(w.validate().is_ok());
        } else {
            assert!(matches!(
                w.validate(),
                Err(IllegalInstruction::IllegalRegister)
            ));
        }
    }
    w.instruction.regs = 10;
    assert!(matches!(
        w.validate(),
        Err(IllegalInstruction::IllegalRegister)
    ));
}

#[cfg(all(feature = "atomic32", feature = "atomic64"))]
#[test]
fn test_atomic_validation() {
    let mut i = Instruction::from_raw(Instruction::pack(
        BPF_ATOMIC | BPF_B | BPF_STX,
        0,
        0,
        0,
        BPF_ATOMIC_FETCH | BPF_ATOMIC_ADD,
    ));
    assert!(matches!(
        i.is_atomic_store_valid(),
        Err(IllegalInstruction::UnsupportedAtomicWidth)
    ));
    i.opcode = BPF_ATOMIC | BPF_DW | BPF_STX;
    assert!(i.is_atomic_store_valid().is_ok());
    i.regs = 0xb;
    assert_eq!(i.dst_reg(), 11);
    assert!(matches!(
        i.is_atomic_store_valid(),
        Err(IllegalInstruction::IllegalRegister)
    ));
    i.regs = 0xb0;
    assert_eq!(i.src_reg(), 11);
    assert!(matches!(
        i.is_atomic_store_valid(),
        Err(IllegalInstruction::IllegalRegister)
    ));
    assert!(Instruction::from_raw(Instruction::pack(
        BPF_ATOMIC | BPF_W | BPF_STX,
        0,
        0,
        0,
        BPF_ATOMIC_ADD,
    ))
    .validate()
    .is_ok());
}
