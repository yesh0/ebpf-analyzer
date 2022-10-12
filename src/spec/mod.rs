use core::fmt::Debug;

use ebpf_consts::*;
use ebpf_consts::mask::*;

pub mod state;
pub mod value;

pub type CodeOffset = usize;

/// BPF instruction
///
/// The member functions are intentionally passing by value.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Instruction {
    pub opcode: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

/// BPF wide instruction
pub struct WideInstruction {
    pub instruction: Instruction,
    pub imm: i64,
}

/// Parsed instruction result
pub enum ParsedInstruction {
    None,
    Instruction(Instruction),
    WideInstruction(WideInstruction),
}

/// Basic jump instruction classification
pub enum JumpInstruction {
    Unconditional(i16),
    Conditional(i16),
    Exit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IllegalInstruction {
    IllegalOpCode,
    IllegalRegister,
    IllegalInstruction,
    LegacyInstruction,
    UnusedFieldNotZeroed,
    UnsupportedAtomicWidth,
    UnalignedJump,
    OutOfBoundJump,
}

impl Instruction {
    pub fn opcode(code: u64) -> u8 {
        (code & BPF_OPCODE_MASK) as u8
    }

    /// Constructs an instruction from code at `pc`
    ///
    /// It does not check for instruction validity
    pub fn from(code: &[u64], pc: usize) -> ParsedInstruction {
        let insn = Instruction::from_raw(code[pc]);
        if insn.is_wide() {
            if pc + 1 >= code.len() {
                ParsedInstruction::None
            } else {
                ParsedInstruction::WideInstruction(WideInstruction {
                    instruction: insn,
                    imm: code[pc + 1] as i64,
                })
            }
        } else {
            ParsedInstruction::Instruction(insn)
        }
    }

    /// Constructs an instruction from a encoded code
    pub fn from_raw(encoded: u64) -> Instruction {
        Instruction {
            opcode: (encoded & 0xFF) as u8,
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
    pub fn validate(self) -> Option<IllegalInstruction> {
        match self.opcode & BPF_OPCODE_CLASS_MASK {
            BPF_LD => {
                if self.is_wide() {
                    if self.off == 0 && self.src_reg() == 0 {
                        if self.dst_reg() < WRITABLE_REGISTER_COUNT {
                            None
                        } else {
                            Some(IllegalInstruction::IllegalRegister)
                        }
                    } else {
                        Some(IllegalInstruction::UnusedFieldNotZeroed)
                    }
                } else {
                    Some(IllegalInstruction::LegacyInstruction)
                }
            }
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
            _ => unreachable!()
        }
    }

    pub fn src_reg(self) -> u8 {
        self.regs >> 4
    }

    pub fn dst_reg(self) -> u8 {
        self.regs & 0x0F
    }

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
    fn is_store_load_valid<const LOAD: bool, const IMM: bool>(self) -> Option<IllegalInstruction> {
        if (self.opcode & BPF_OPCODE_MODIFIER_MASK) != BPF_MEM {
            return Some(IllegalInstruction::IllegalOpCode);
        }

        if LOAD {
            if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                return Some(IllegalInstruction::IllegalRegister);
            }
        } else {
            if self.dst_reg() >= READABLE_REGISTER_COUNT {
                return Some(IllegalInstruction::IllegalRegister);
            }
        }

        if IMM {
            if self.src_reg() != 0 {
                return Some(IllegalInstruction::UnusedFieldNotZeroed);
            }
        } else {
            if self.src_reg() >= READABLE_REGISTER_COUNT {
                return Some(IllegalInstruction::IllegalRegister);
            }
            if self.imm != 0 {
                return Some(IllegalInstruction::UnusedFieldNotZeroed);
            }
        }

        None
    }

    /// Checks if a jump instruction is valid
    ///
    /// 1. BPF_EXIT does not use any other fields;
    /// 2. BPF_CALL calls the function specified in the immediate number;
    /// 3. BPF_JA jumps to the offset unconditionally;
    /// 4. Other instructions either:
    ///    a) compares dst_reg against the immediate number;
    ///    b) or compares dst_reg against the src_reg.
    fn is_jump_valid<const XLEN: u8>(self) -> Option<IllegalInstruction> {
        match self.opcode & BPF_OPCODE_JMP_MASK {
            0xE0 => Some(IllegalInstruction::IllegalOpCode),
            0xF0 => Some(IllegalInstruction::IllegalOpCode),
            BPF_JA => {
                if XLEN == 32 {
                    Some(IllegalInstruction::IllegalInstruction)
                } else {
                    if self.regs == 0 && self.imm == 0 {
                        None
                    } else {
                        Some(IllegalInstruction::UnusedFieldNotZeroed)
                    }
                }
            }
            BPF_CALL => {
                // TODO: support pseudo tail call
                if self.regs == 0 && self.off == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            BPF_EXIT => {
                if XLEN == 32 {
                    Some(IllegalInstruction::IllegalInstruction)
                } else {
                    if self.regs == 0 && self.imm == 0 && self.off == 0 {
                        None
                    } else {
                        Some(IllegalInstruction::UnusedFieldNotZeroed)
                    }
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
    ///
    /// FIXME: Descriptions from https://docs.kernel.org/bpf/instruction-set.html
    /// conflicts with https://github.com/iovisor/bpf-docs/blob/master/eBPF.md about BPF_NEG.
    /// Please double check against the linux implementation.
    fn is_arithmetic_valid(self) -> Option<IllegalInstruction> {
        if self.off != 0 {
            return Some(IllegalInstruction::UnusedFieldNotZeroed);
        }

        match self.opcode & BPF_OPCODE_ALU_MASK {
            0xE0 => Some(IllegalInstruction::IllegalOpCode),
            0xF0 => Some(IllegalInstruction::IllegalOpCode),
            BPF_NEG => {
                if self.src_reg() != 0 {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                } else if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                    Some(IllegalInstruction::IllegalRegister)
                } else if (self.opcode & BPF_X) != 0 {
                    Some(IllegalInstruction::IllegalOpCode)
                } else {
                    None
                }
            }
            BPF_END => {
                if (self.opcode & BPF_OPCODE_CLASS_MASK) == BPF_ALU64 {
                    Some(IllegalInstruction::IllegalOpCode)
                } else if self.src_reg() != 0 {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                } else if self.dst_reg() < WRITABLE_REGISTER_COUNT {
                    if [16, 32, 64].contains(&self.imm) {
                        None
                    } else {
                        Some(IllegalInstruction::IllegalInstruction)
                    }
                } else {
                    Some(IllegalInstruction::IllegalRegister)
                }
            }
            _ => self.is_arithmetic_registers_valid::<true>(),
        }
    }

    pub fn is_arithmetic_source_immediate(self) -> bool {
        (self.opcode & BPF_OPCODE_SRC_MASK) == 0
    }

    fn is_arithmetic_registers_valid<const WRITES_TO_DST: bool>(
        self,
    ) -> Option<IllegalInstruction> {
        if WRITES_TO_DST {
            if self.dst_reg() >= WRITABLE_REGISTER_COUNT {
                return Some(IllegalInstruction::IllegalRegister);
            }
        } else {
            if self.dst_reg() >= READABLE_REGISTER_COUNT {
                return Some(IllegalInstruction::IllegalRegister);
            }
        }

        if self.is_arithmetic_source_immediate() {
            if self.src_reg() == 0 {
                None
            } else {
                Some(IllegalInstruction::UnusedFieldNotZeroed)
            }
        } else {
            if self.imm == 0 {
                if self.src_reg() < READABLE_REGISTER_COUNT {
                    None
                } else {
                    Some(IllegalInstruction::IllegalRegister)
                }
            } else {
                Some(IllegalInstruction::UnusedFieldNotZeroed)
            }
        }
    }

    /// Checks an atomic instruction
    ///
    /// 1. BPF_XCHG: Exchanges the original value into src_reg;
    /// 2. BPF_CMPXCHG: The value is stored into R0, src_reg not modified.
    /// 3. Other instructions store into src_reg if the BPF_FETCH flag is set.
    fn is_atomic_store_valid(self) -> Option<IllegalInstruction> {
        let operant_size: u8 = self.opcode & BPF_OPCODE_SIZE_MASK;
        if !((cfg!(atomic64) && operant_size == BPF_DW) || (cfg!(atomic32) && operant_size == BPF_W)) {
            return Some(IllegalInstruction::UnsupportedAtomicWidth);
        }

        match self.imm {
            BPF_ATOMIC_XCHG => {
                if self.src_reg() >= WRITABLE_REGISTER_COUNT
                    || self.dst_reg() >= READABLE_REGISTER_COUNT
                {
                    return Some(IllegalInstruction::IllegalRegister);
                }
                if self.imm == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            _ => {
                if self.dst_reg() >= READABLE_REGISTER_COUNT {
                    return Some(IllegalInstruction::IllegalRegister);
                }
                if self.imm != BPF_ATOMIC_CMPXCHG && (self.imm & BPF_ATOMIC_FETCH) != 0 {
                    if self.src_reg() >= WRITABLE_REGISTER_COUNT {
                        return Some(IllegalInstruction::IllegalRegister);
                    }
                } else {
                    if self.src_reg() >= READABLE_REGISTER_COUNT {
                        return Some(IllegalInstruction::IllegalRegister);
                    }
                }
                if self.imm == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
        }
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
