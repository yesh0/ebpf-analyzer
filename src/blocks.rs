//! Block level validation

use core::cmp::Ordering;

use alloc::vec::Vec;

use crate::{
    analyzer::VerificationError,
    spec::{CodeOffset, IllegalInstruction, Instruction, JumpInstruction, ParsedInstruction},
};

/// Id of a code block
pub type BlockId = usize;

/// Block id of a terminal block (pointed to by `BPF_EXIT` blocks)
pub const TERMINAL_PSEUDO_BLOCK: usize = usize::MAX;

/// Functions
pub struct FunctionBlock {
    /// Start offsets of each block
    pub block_starts: Vec<CodeOffset>,
    /// `from[this_block]` points to the blocks that this_block may jump to
    pub from: Vec<Vec<usize>>,
    /// `to[this_block]` points to the blocks that may jump to this_block
    pub to: Vec<Vec<usize>>,
}

/// A collection of [FunctionBlock]
pub type FunctionBlocks = Vec<FunctionBlock>;

/// Information about an eBPF program
pub struct ProgramInfo {
    /// Functions
    pub functions: FunctionBlocks,
    /// Used map file descriptors
    pub maps: Vec<i32>,
}

/// Error when we cannot parse the code into blocks
#[derive(Debug, PartialEq, Eq)]
pub enum IllegalStructure {
    /// The last block does not ends with an unconditional jump or exit instruction
    BlockOpenEnd,
    /// An empty block or program
    Empty,
}

/// Boundaries
struct Boundaries {
    /// Function addresses
    functions: Vec<CodeOffset>,
    /// Block boundaries, including a terminal label (at `code.len()`)
    labels: Vec<CodeOffset>,
}

impl Boundaries {
    /// Checks if a jump is somehow valid
    ///
    /// Note that jumps might jump into the middle of wide instructions,
    /// so you will still need to check jumps, that is, block borders,
    /// against byte code borders.
    fn checked_jump(
        code: &[u64],
        pc: CodeOffset,
        offset: i32,
    ) -> Result<CodeOffset, IllegalInstruction> {
        // Checks if the target PC is out of bounds
        let target = if let Some(t) = pc.checked_add_signed(offset as isize) {
            t
        } else {
            return Err(IllegalInstruction::OutOfBoundJump);
        };

        let bound = if offset >= 0 { code.len() } else { pc - 1 };

        // Checks if the target instruction is out of bounds
        let size = match Instruction::from(code, target) {
            ParsedInstruction::None => return Err(IllegalInstruction::IllegalInstruction),
            ParsedInstruction::Instruction(_) => 1,
            ParsedInstruction::WideInstruction(_) => 2,
        };
        if let Some(end) = target.checked_add(size) {
            if end <= bound {
                // Note that we might still jump into the middle of a wide instruction
                return Ok(target);
            }
        }

        Err(IllegalInstruction::OutOfBoundJump)
    }

    /// Compute the absolute PC that a jump instruction jumps to
    ///
    /// You should only use this after checking all jumps.
    fn unchecked_jump(pc: CodeOffset, offset: i16) -> CodeOffset {
        pc.checked_add_signed(offset as isize).unwrap()
    }

    /// Split the code into blocks judging from jump instructions and function calls
    ///
    /// It checks whether the control flow will jump out of the code boundaries.
    ///
    /// TODO: It does not handle tail calls yet, which should behave like a BPF_EXIT.
    fn sorted_boundaries(code: &[u64], info: &mut ProgramInfo) -> Result<Self, IllegalInstruction> {
        let mut labels: Vec<CodeOffset> = Vec::new();
        let mut functions: Vec<CodeOffset> = Vec::new();
        labels.push(0);
        functions.push(0);
        let mut pc = 0 as CodeOffset;
        while pc < code.len() {
            let parsed = Instruction::from(code, pc);
            parsed.validate()?;
            let (insn, pc_inc) = match parsed {
                ParsedInstruction::None => return Err(IllegalInstruction::IllegalInstruction),
                ParsedInstruction::Instruction(i) => (i, 1),
                ParsedInstruction::WideInstruction(w) => (w.instruction, 2),
            };

            // Detect functions
            if let Some(offset) = insn.is_pseudo_call().or_else(|| insn.is_ldimm64_func()) {
                // It seems the two instructions, despite one being a wide isns,
                // both have the target address as `pc + 1`.
                if let Ok(target) = Self::checked_jump(code, pc + 1, offset) {
                    functions.push(target);
                } else {
                    return Err(IllegalInstruction::OutOfBoundFunction);
                }
            }

            // Detect used maps
            if let Some(fd) = insn.is_ldimm64_map_fd() {
                if !info.maps.contains(&fd) {
                    info.maps.push(fd);
                }
            }

            pc += pc_inc;

            if let Some(jump) = insn.jumps_to() {
                match jump {
                    JumpInstruction::Exit => labels.push(pc),
                    JumpInstruction::Unconditional(offset) => {
                        labels.push(pc);
                        labels.push(Self::checked_jump(code, pc, offset as i32)?);
                    }
                    JumpInstruction::Conditional(offset) => {
                        labels.push(pc);
                        labels.push(Self::checked_jump(code, pc, offset as i32)?);
                    }
                }
            }
        }
        functions.sort_unstable();
        functions.dedup();
        labels.sort_unstable();
        labels.dedup();
        Ok(Self { functions, labels })
    }

    /// Builds a directed graph from the control flow
    ///
    /// It also checks whether the jump destinations (block borders) match byte code borders.
    fn parse_functions(&self, code: &[u64]) -> Result<Vec<FunctionBlock>, VerificationError> {
        let mut current_label = 0usize;
        let mut functions = Vec::new();
        functions.reserve(self.functions.len());
        for i in 0..self.functions.len() {
            let start = self.functions[i];
            let end = if i + 1 < self.functions.len() {
                self.functions[i + 1]
            } else {
                code.len()
            };
            let (labels, function) = self.parse_graph((start, end), current_label, code)?;
            current_label += labels;
            functions.push(function);
        }
        Ok(functions)
    }

    fn parse_graph(
        &self,
        (start, end): (CodeOffset, CodeOffset),
        label_i: usize,
        code: &[u64],
    ) -> Result<(usize, FunctionBlock), VerificationError> {
        let labels = self.get_labels_within(label_i, (start, end))?;
        let block_count = labels.len() - 1;

        let mut from: Vec<Vec<BlockId>> = Vec::new();
        let mut to: Vec<Vec<BlockId>> = Vec::new();
        from.resize(block_count, Vec::new());
        to.resize(block_count, Vec::new());

        for (block_id, block) in labels.windows(2).enumerate() {
            let (mut pc, block_end) = (block[0], block[1]);

            while pc < block_end {
                let (instruction, pc_inc) = match Instruction::from(code, pc) {
                    ParsedInstruction::None => {
                        unreachable!("Should have verified in sorted_block_boundaries")
                    }
                    ParsedInstruction::Instruction(i) => (i, 1),
                    ParsedInstruction::WideInstruction(w) => (w.instruction, 2),
                };
                pc += pc_inc;

                if pc == block_end {
                    // Maybe the following code needs some cleanup...
                    //
                    // Mainly, code blocks are connected either because:
                    // Cond 1. they are neighbouring and the first block does not jumps away unconditionally;
                    // Cond 2. A block jumps there (and we need a binary search).
                    let jumps_to = match instruction.jumps_to() {
                        // Cond 2.
                        Some(JumpInstruction::Unconditional(offset)) => offset,
                        // Cond 1. & Cond 2.
                        Some(JumpInstruction::Conditional(offset))
                            if block_id + 1 < block_count =>
                        {
                            from[block_id].push(block_id + 1);
                            to[block_id + 1].push(block_id);
                            offset
                        }
                        // Cond 2.
                        Some(JumpInstruction::Exit) => {
                            from[block_id].push(TERMINAL_PSEUDO_BLOCK);
                            continue;
                        }
                        // Cond1
                        None if block_id + 1 < block_count => {
                            from[block_id].push(block_id + 1);
                            to[block_id + 1].push(block_id);
                            continue;
                        }
                        _ => {
                            return Err(VerificationError::IllegalStructure(
                                IllegalStructure::BlockOpenEnd,
                            ))
                        }
                    };
                    // Cond 2 processing
                    if let Ok(dst) = labels.binary_search(&Self::unchecked_jump(pc, jumps_to)) {
                        if dst < block_count {
                            from[block_id].push(dst);
                            to[dst].push(block_id);
                            continue;
                        }
                    }
                    return Err(VerificationError::IllegalInstruction(
                        IllegalInstruction::OutOfBoundJump,
                    ));
                }
            }
            if pc != block_end {
                // When the last instruction is a 128-bit one
                // and some instructions try to jump into the middle of it.
                return Err(VerificationError::IllegalInstruction(
                    IllegalInstruction::UnalignedJump,
                ));
            }
        }
        Ok((
            block_count,
            FunctionBlock {
                block_starts: Vec::from(&labels[0..(labels.len() - 1)]),
                from,
                to,
            },
        ))
    }

    /// Gets a slice of all labels with a range of [CodeOffset]
    ///
    /// It expects both ends are labeled and includes both in the returned slice.
    ///
    /// For example, with `labels: [..., func1, label1, label2, func2, ...]`,
    /// calling this function with `label_i` pointing to `func1`, `(start, end) = (func1, func2)`
    /// gets `&[func1, label1, label2, func2]`.
    fn get_labels_within(
        &self,
        label_i: usize,
        (start, end): (CodeOffset, CodeOffset),
    ) -> Result<&[usize], VerificationError> {
        if label_i >= self.labels.len() || self.labels[label_i] != start {
            // Open end in the previous function
            // Probably it is a redundant check.
            return Err(VerificationError::IllegalStructure(
                IllegalStructure::BlockOpenEnd,
            ));
        }
        for i in (label_i + 1)..self.labels.len() {
            match self.labels[i].cmp(&end) {
                Ordering::Equal => return Ok(&self.labels[label_i..=i]),
                Ordering::Greater => return Err(VerificationError::IllegalStructure(
                    IllegalStructure::BlockOpenEnd,
                )),
                _ => {},
            }
        }
        Err(VerificationError::IllegalStructure(
            IllegalStructure::BlockOpenEnd,
        ))
    }
}

impl FunctionBlock {
    /// Parses the eBPF code into function blocks
    pub fn new(code: &[u64], info: &mut ProgramInfo) -> Result<Vec<FunctionBlock>, VerificationError> {
        let boundaries = Boundaries::sorted_boundaries(code, info)?;
        boundaries.parse_functions(code)
    }

    /// Returns the function count
    pub fn block_count(&self) -> usize {
        self.block_starts.len()
    }
}

impl ProgramInfo {
    /// Parses the eBPF code and gathers information
    pub fn new(code: &[u64]) -> Result<ProgramInfo, VerificationError> {
        let mut info = Self {
            functions: Vec::new(),
            maps: Vec::new(),
        };
        info.functions = FunctionBlock::new(code, &mut info)?;
        Ok(info)
    }
}

#[cfg(test)]
use ebpf_consts::*;

#[test]
pub fn test_inter_function_jump() {
    let code: &[u64] = &[
        // Code:
        //   main:
        // 0: call test (pc + 2)
        // 1: if R0 == 0 goto test (pc + 1)
        // 2: exit
        //   test:
        // 3: exit

        // main:
        Instruction::pack(BPF_JMP_CALL, BPF_CALL_PSEUDO, 0, 0, 2),
        Instruction::pack(BPF_JMP | BPF_K | BPF_JEQ, 0, 0, 1, 0),
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
        // test:
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
    ];
    let result = ProgramInfo::new(code);
    match result.err() {
        Some(VerificationError::IllegalInstruction(IllegalInstruction::OutOfBoundJump)) => {}
        _ => panic!(),
    }

    let normal: &[u64] = &[
        // Code:
        //   main:
        // 0: call test (pc + 2)
        // 1: R0 = 0
        // 2: exit
        //   test:
        // 3: exit

        // main:
        Instruction::pack(BPF_JMP_CALL, BPF_CALL_PSEUDO, 0, 0, 2),
        Instruction::pack(BPF_ALU | BPF_K | BPF_MOV, 0, 0, 0, 0),
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
        // test:
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
    ];
    let result = ProgramInfo::new(normal);
    assert!(result.is_ok());
    assert!(result.ok().unwrap().functions.len() == 2);

    let complex_normal: &[u64] = &[
        // Code:
        //   main:
        // 0: call test (pc + 5)
        // 1: R0 = 0
        // 2: exit
        //   recur:
        // 3: R0 = 0
        // 4: call recur (pc - 2)
        // 5: exit
        //   test:
        // 6: call recur (pc - 4)
        // 7: R0 = 0
        // 8: exit

        // main:
        Instruction::pack(BPF_JMP_CALL, BPF_CALL_PSEUDO, 0, 0, 5),
        Instruction::pack(BPF_ALU | BPF_K | BPF_MOV, 0, 0, 0, 0),
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
        // rec:
        Instruction::pack(BPF_ALU | BPF_K | BPF_MOV, 0, 0, 0, 0),
        Instruction::pack(BPF_JMP_CALL, BPF_CALL_PSEUDO, 0, 0, -2),
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
        // test:
        Instruction::pack(BPF_JMP_CALL, BPF_CALL_PSEUDO, 0, 0, -4),
        Instruction::pack(BPF_ALU | BPF_K | BPF_MOV, 0, 0, 0, 0),
        Instruction::pack(BPF_JMP_EXIT, 0, 0, 0, 0),
    ];
    let result = ProgramInfo::new(complex_normal);
    assert!(result.is_ok());
    assert!(result.ok().unwrap().functions.len() == 3);
}
