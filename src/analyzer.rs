use alloc::vec::Vec;

use crate::{
    blocks::{CodeBlocks, IllegalStructure, TERMINAL_PSEUDO_BLOCK},
    spec::IllegalInstruction,
};

pub struct Analyzer;

#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    IllegalStructure(IllegalStructure),
    IllegalInstruction(IllegalInstruction),
    IllegalGraph,
    IllegalStateChange,
}

impl Analyzer {
    pub fn analyze(code: &[u64]) -> Result<usize, VerificationError> {
        match CodeBlocks::new(code) {
            Ok(blocks) => {
                Analyzer::has_unreachable_block(&blocks)?;
                Analyzer::has_forbidden_state_change(code, &blocks)?;
                Ok(0)
            }
            Err(err) => Err(err)
        }
    }

    /// Runs a BFS to see if there is any unreachable blocks
    fn has_unreachable_block(code: &CodeBlocks) -> Result<(), VerificationError> {
        let mut reached: Vec<bool> = Vec::new();
        reached.resize(code.block_count(), false);

        let mut stack: Vec<usize> = Vec::new();
        stack.push(0);
        while let Some(block) = stack.pop() {
            if !reached[block] {
                reached[block] = true;
                if code.from[block].is_empty() {
                    return Err(VerificationError::IllegalStructure(IllegalStructure::BlockOpenEnd));
                }
                for to in &code.from[block] {
                    if *to != TERMINAL_PSEUDO_BLOCK {
                        stack.push(*to);
                    }
                }
            }
        }

        if reached.iter().any(|b| !b) {
            Err(VerificationError::IllegalGraph)
        } else {
            Ok(())
        }
    }

    fn has_forbidden_state_change(_code: &[u64], _blocks: &CodeBlocks) -> Result<(), VerificationError> {
        // todo!()
        Ok(())
    }
}
