use alloc::vec::Vec;

use crate::{
    analyzer::VerificationError,
    spec::{CodeOffset, IllegalInstruction, Instruction, JumpInstruction, ParsedInstruction},
};

pub type ByteOffset = usize;
pub type BlockId = usize;

pub const TERMINAL_PSEUDO_BLOCK: usize = usize::MAX;

pub struct CodeBlocks {
    /// Start offsets of each block
    pub block_starts: Vec<CodeOffset>,
    /// `from[this_block]` points to the blocks that this_block may jump to
    pub from: Vec<Vec<usize>>,
    /// `to[this_block]` points to the blocks that may jump to this_block
    pub to: Vec<Vec<usize>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IllegalStructure {
    BlockOpenEnd,
    Empty,
}

impl CodeBlocks {
    /// Checks if a jump is somehow valid
    ///
    /// Note that jumps might jump into the middle of wide instructions,
    /// so you will still need to check jumps, that is, block borders,
    /// against byte code borders.
    fn checked_jump(
        code: &[u64],
        pc: CodeOffset,
        offset: i16,
    ) -> Result<CodeOffset, IllegalInstruction> {
        let offset = offset as i32;

        // Checks if the target PC is out of bounds
        let (target, bound) = if offset >= 0 {
            if code.len() - pc > offset as usize {
                (pc + offset as usize, code.len())
            } else {
                return Err(IllegalInstruction::OutOfBoundJump);
            }
        } else {
            if (-offset) as usize <= pc {
                (pc - (-offset as usize), pc - 1)
            } else {
                return Err(IllegalInstruction::OutOfBoundJump);
            }
        };

        // Checks if the target instruction is out of bounds
        let size = match Instruction::from(code, target) {
            ParsedInstruction::None => return Err(IllegalInstruction::IllegalInstruction),
            ParsedInstruction::Instruction(_) => 1,
            ParsedInstruction::WideInstruction(_) => 2,
        };
        if bound - size < target {
            return Err(IllegalInstruction::OutOfBoundJump);
        }

        // Note that we might still jump into the middle of a wide instruction
        return Ok(target);
    }

    /// Compute the absolute PC that a jump instruction jumps to
    ///
    /// You should only use this after checking all jumps.
    fn unchecked_jump(pc: CodeOffset, offset: i16) -> CodeOffset {
        if offset >= 0 {
            pc + offset as usize
        } else {
            pc - (-offset) as usize
        }
    }

    /// Split the code into blocks judging from jump instructions
    ///
    /// It checks whether the control flow will jump out of the code boundaries.
    fn sorted_block_boundaries(code: &[u64]) -> Result<Vec<CodeOffset>, IllegalInstruction> {
        let mut labels: Vec<CodeOffset> = Vec::new();
        labels.push(0);
        let mut pc = 0 as CodeOffset;
        while pc < code.len() {
            let parsed = Instruction::from(code, pc);
            parsed.validate()?;
            let (insn, pc_inc) = match parsed {
                ParsedInstruction::None => return Err(IllegalInstruction::IllegalInstruction),
                ParsedInstruction::Instruction(i) => (i, 1),
                ParsedInstruction::WideInstruction(w) => (w.instruction, 2),
            };
            pc += pc_inc;

            if let Some(jump) = insn.jumps_to() {
                match jump {
                    JumpInstruction::Exit => labels.push(pc),
                    JumpInstruction::Unconditional(offset) => {
                        labels.push(pc);
                        match CodeBlocks::checked_jump(code, pc, offset) {
                            Ok(target) => labels.push(target),
                            Err(err) => return Err(err),
                        }
                    }
                    JumpInstruction::Conditional(offset) => {
                        labels.push(pc);
                        match CodeBlocks::checked_jump(code, pc, offset) {
                            Ok(target) => labels.push(target),
                            Err(err) => return Err(err),
                        }
                    }
                }
            }
        }
        labels.sort_unstable();
        labels.dedup();
        Ok(labels)
    }

    /// Builds a directed graph from the control flow
    ///
    /// It also checks whether the jump destinations (block borders) match byte code borders.
    fn parse_graph(
        code: &[u64],
        boundaries: &Vec<CodeOffset>,
    ) -> Result<(Vec<Vec<BlockId>>, Vec<Vec<BlockId>>), VerificationError> {
        let mut from: Vec<Vec<BlockId>> = Vec::new();
        let mut to: Vec<Vec<BlockId>> = Vec::new();
        let block_count = boundaries.len() - 1;
        from.resize(block_count, Vec::new());
        to.resize(block_count, Vec::new());

        let mut pc = 0 as CodeOffset;
        if code.last().is_some() {
            for block_id in 0..block_count {
                let block_end = boundaries[block_id + 1];
                while pc < block_end {
                    let (instruction, pc_inc) = match Instruction::from(code, pc) {
                        ParsedInstruction::None => {
                            panic!("Should have verified in sorted_block_boundaries")
                        }
                        ParsedInstruction::Instruction(i) => (i, 1),
                        ParsedInstruction::WideInstruction(w) => (w.instruction, 2),
                    };
                    pc += pc_inc;

                    if pc == block_end {
                        if let Some(jump) = instruction.jumps_to() {
                            if let Some(offset) = match jump {
                                JumpInstruction::Unconditional(offset) => Some(offset),
                                JumpInstruction::Conditional(offset) => {
                                    if block_id + 1 < block_count {
                                        from[block_id].push(block_id + 1);
                                        to[block_id + 1].push(block_id);
                                        Some(offset)
                                    } else {
                                        return Err(VerificationError::IllegalStructure(
                                            IllegalStructure::BlockOpenEnd,
                                        ));
                                    }
                                }
                                JumpInstruction::Exit => {
                                    from[block_id].push(TERMINAL_PSEUDO_BLOCK);
                                    None
                                }
                            } {
                                let dst = boundaries
                                    .binary_search(&CodeBlocks::unchecked_jump(pc, offset))
                                    .ok()
                                    .unwrap();
                                from[block_id].push(dst);
                                to[dst].push(block_id);
                            }
                        } else {
                            if block_id + 1 < block_count {
                                from[block_id].push(block_id + 1);
                                to[block_id + 1].push(block_id);
                            } else {
                                return Err(VerificationError::IllegalStructure(
                                    IllegalStructure::BlockOpenEnd,
                                ));
                            }
                        }
                    }
                }
                if pc != block_end {
                    return Err(VerificationError::IllegalInstruction(
                        IllegalInstruction::UnalignedJump,
                    ));
                }
            }
            if pc == code.len() {
                Ok((from, to))
            } else {
                Err(VerificationError::IllegalInstruction(
                    IllegalInstruction::UnalignedJump,
                ))
            }
        } else {
            Err(VerificationError::IllegalStructure(IllegalStructure::Empty))
        }
    }

    pub fn new(code: &[u64]) -> Result<CodeBlocks, VerificationError> {
        match CodeBlocks::sorted_block_boundaries(code) {
            Ok(mut boundaries) => match CodeBlocks::parse_graph(code, &boundaries) {
                Ok((from, to)) => {
                    boundaries.pop();
                    Ok(CodeBlocks {
                        block_starts: boundaries,
                        from,
                        to,
                    })
                }
                Err(err) => Err(err),
            },
            Err(err) => Err(VerificationError::IllegalInstruction(err)),
        }
    }

    pub fn block_count(&self) -> usize {
        self.block_starts.len()
    }
}
