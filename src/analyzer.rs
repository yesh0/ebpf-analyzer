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
                if let Some(err) = Analyzer::has_unreachable_block(&blocks) {
                    Err(err)
                } else if let Some(err) = Analyzer::has_forbidden_state_change(code, &blocks) {
                    Err(err)
                } else {
                    Ok(0)
                }
            }
            Err(err) => Err(err)
        }
    }

    /// Runs a BFS to see if there is any unreachable blocks
    fn has_unreachable_block(code: &CodeBlocks) -> Option<VerificationError> {
        let mut reached: Vec<bool> = Vec::new();
        reached.resize(code.block_count(), false);

        let mut stack: Vec<usize> = Vec::new();
        stack.push(0);
        while let Some(block) = stack.pop() {
            if !reached[block] {
                reached[block] = true;
                if code.from[block].is_empty() {
                    return Some(VerificationError::IllegalStructure(IllegalStructure::BlockOpenEnd));
                }
                for to in &code.from[block] {
                    if *to != TERMINAL_PSEUDO_BLOCK {
                        stack.push(*to);
                    }
                }
            }
        }

        if reached.iter().any(|b| !b) {
            Some(VerificationError::IllegalGraph)
        } else {
            None
        }
    }

    fn has_forbidden_state_change(_code: &[u64], _blocks: &CodeBlocks) -> Option<VerificationError> {
        // todo!()
        None
    }
}
