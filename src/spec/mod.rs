use core::fmt::Debug;

use num_traits::FromPrimitive;

use self::{
    consts::{
        InstructionClass, BPF_ALU_END, BPF_ATOMIC_CMPXCHG, BPF_ATOMIC_FETCH, BPF_ATOMIC_XCHG,
        BPF_CALL, BPF_DW, BPF_EXIT, BPF_JA, BPF_LD, BPF_MODE_ATOMIC, BPF_MODE_IMM, BPF_MODE_MEM,
        BPF_W,
    },
    state::{READABLE_REGISTER_COUNT, WRITABLE_REGISTER_COUNT},
};

pub mod consts;
pub mod state;

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

#[derive(Debug)]
pub enum IllegalInstruction {
    IllegalOpCode,
    IllegalRegister,
    IllegalInstruction,
    LegacyInstruction,
    UnusedFieldNotZeroed,
}

impl Instruction {
    /// Constructs an instruction from code at `pc`
    ///
    /// It does not check for instruction validity
    pub fn from(code: &[u64], pc: usize) -> ParsedInstruction {
        let encoded = code[pc];
        let insn = Instruction {
            opcode: (encoded & 0xFF) as u8,
            regs: ((encoded >> 8) & 0xFF) as u8,
            off: ((encoded >> 16) & 0xFFFF) as i16,
            imm: (encoded >> 32) as i32,
        };
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

    /// Checks whether an instruction is a valid one
    ///
    /// The following checks are performed:
    /// 1. Legacy instructions (BPF Packet access instructions) are disallowed;
    /// 2. Unused fields must be zeroed;
    /// 3. R10 is read-only while the other ten are writable;
    pub fn validate(self) -> Option<IllegalInstruction> {
        match self.code_type() {
            InstructionClass::LoadMisc => {
                if self.opcode == (BPF_LD | (BPF_DW << 3) | (BPF_MODE_IMM << 5)) {
                    if self.off == 0 && self.src_reg() == 0 && self.imm == 0 {
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
            InstructionClass::LoadIntoRegister => self.is_store_load_valid::<true, false>(),
            InstructionClass::StoreFromImmediate => self.is_store_load_valid::<false, true>(),
            InstructionClass::StoreFromRegister => {
                if (self.opcode >> 5) == BPF_MODE_ATOMIC {
                    self.is_atomic_store_valid()
                } else {
                    self.is_store_load_valid::<false, false>()
                }
            }
            InstructionClass::Arithmetric32 => self.is_arithmetic_valid(),
            InstructionClass::Jump32 => self.is_jump_valid::<32>(),
            InstructionClass::Jump64 => self.is_jump_valid::<64>(),
            InstructionClass::Arithmetric64 => self.is_arithmetic_valid(),
        }
    }

    pub fn code_type(self) -> InstructionClass {
        FromPrimitive::from_u8(self.opcode & 0b00000111).unwrap()
    }

    pub fn src_reg(self) -> u8 {
        self.regs >> 4
    }

    pub fn dst_reg(self) -> u8 {
        self.regs & 0x0F
    }

    /// `true` if this instruction is a wide instruction (i.e. taking 128 bits)
    ///
    /// Currently, there is only one wide instruction.
    pub fn is_wide(self) -> bool {
        self.opcode == (BPF_LD | (BPF_DW << 3) | (BPF_MODE_IMM << 5))
    }

    /// Checks a store / load instruction
    ///
    /// - BPF_MEM:
    ///   - BPF_LDX: Requires writable dst_reg, readable src_reg and off;
    ///   - BPF_STX: Requires readable dst_reg, readable src_reg and off;
    ///   - BPF_ST : Requires readable dst_reg, imm and off.
    fn is_store_load_valid<const LOAD: bool, const IMM: bool>(self) -> Option<IllegalInstruction> {
        if (self.opcode >> 5) != BPF_MODE_MEM {
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
        match self.opcode >> 4 {
            0x0E => Some(IllegalInstruction::IllegalOpCode),
            0x0F => Some(IllegalInstruction::IllegalOpCode),
            BPF_JA => {
                if self.regs == 0 && self.imm == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            BPF_CALL => {
                if self.regs == 0 && self.off == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            BPF_EXIT => {
                if self.regs == 0 && self.imm == 0 && self.off == 0 {
                    None
                } else {
                    Some(IllegalInstruction::UnusedFieldNotZeroed)
                }
            }
            _ => self.is_arithmetic_registers_valid::<false>(),
        }
    }

    /// Checks if a jump instruction is valid
    ///
    /// 1. None of them uses the offset;
    /// 2. All of them writes to the dst_reg;
    /// 3. BPF_ALU_END operates on dst_reg according to the immediate number;
    /// 4. Others read from either src_reg or the immediate number.
    ///
    /// FIXME: Descriptions from https://docs.kernel.org/bpf/instruction-set.html
    /// conflicts with https://github.com/iovisor/bpf-docs/blob/master/eBPF.md about BPF_NEG.
    /// Please double check against the linux implementation.
    fn is_arithmetic_valid(self) -> Option<IllegalInstruction> {
        if self.off != 0 {
            return Some(IllegalInstruction::UnusedFieldNotZeroed);
        }

        match self.opcode >> 4 {
            0x0E => Some(IllegalInstruction::IllegalOpCode),
            0x0F => Some(IllegalInstruction::IllegalOpCode),
            BPF_ALU_END => {
                if self.src_reg() != 0 {
                    return Some(IllegalInstruction::UnusedFieldNotZeroed);
                }
                if self.dst_reg() < WRITABLE_REGISTER_COUNT {
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
        (self.opcode & 0b00001000) == 0
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
        let operant_size: u8 = (self.opcode >> 3) & 0b11;
        if operant_size != BPF_DW && operant_size != BPF_W {
            return Some(IllegalInstruction::IllegalInstruction);
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
