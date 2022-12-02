//! An analyzer

use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};

use crate::{
    blocks::{FunctionBlock, FunctionBlocks, IllegalStructure, TERMINAL_PSEUDO_BLOCK},
    branch::{
        context::BranchContext,
        vm::{Branch, BranchState, StaticHelpers},
    },
    interpreter::{context::VmContext, run, vm::Vm},
    spec::IllegalInstruction,
};

/// Configuration: how the analyzer checks the code
pub struct AnalyzerConfig<'a> {
    /// Helper function calls used by the function
    pub helpers: StaticHelpers,
    /// How a VM should be setup
    ///
    /// Users may inject parameters here.
    pub setup: &'a dyn Fn(&mut BranchState),
}

/// The analyzer (or eBPF verifier)
pub struct Analyzer;

/// Verification error
#[derive(Debug)]
pub enum VerificationError {
    /// See [IllegalStructure]
    IllegalStructure(IllegalStructure),
    /// Illegal instruction
    IllegalInstruction(IllegalInstruction),
    /// Illegal DAG
    IllegalGraph,
    /// Invalid operation
    IllegalStateChange(Branch),
}

impl From<IllegalInstruction> for VerificationError {
    fn from(err: IllegalInstruction) -> Self {
        Self::IllegalInstruction(err)
    }
}

impl Analyzer {
    /// Analyze an eBPF program
    pub fn analyze(code: &[u64], config: &AnalyzerConfig) -> Result<usize, VerificationError> {
        let blocks = FunctionBlock::new(code)?;
        Analyzer::has_unreachable_block(&blocks)?;
        Analyzer::has_forbidden_state_change(code, &blocks, config)?;
        Ok(0)
    }

    /// Runs a BFS to see if there is any unreachable blocks
    fn has_unreachable_block(blocks: &FunctionBlocks) -> Result<(), VerificationError> {
        for code in blocks {
            let mut reached: Vec<bool> = Vec::new();
            reached.resize(code.block_count(), false);

            let mut stack: Vec<usize> = Vec::new();
            stack.push(0);
            while let Some(block) = stack.pop() {
                if !reached[block] {
                    reached[block] = true;
                    if code.from[block].is_empty() {
                        return Err(VerificationError::IllegalStructure(
                            IllegalStructure::BlockOpenEnd,
                        ));
                    }
                    for to in &code.from[block] {
                        if *to != TERMINAL_PSEUDO_BLOCK {
                            stack.push(*to);
                        }
                    }
                }
            }

            if reached.iter().any(|b| !b) {
                return Err(VerificationError::IllegalGraph);
            }
        }
        Ok(())
    }

    fn has_forbidden_state_change(
        code: &[u64],
        blocks: &FunctionBlocks,
        config: &AnalyzerConfig,
    ) -> Result<(), VerificationError> {
        if blocks.len() != 1 {
            Err(VerificationError::IllegalStructure(IllegalStructure::Empty))
        } else {
            let mut branches = BranchContext::new();
            let mut branch = BranchState::new(config.helpers);
            (config.setup)(&mut branch);
            branches.add_pending_branch(Rc::new(RefCell::new(branch)));
            while let Some(branch) = branches.next() {
                let mut vm = branch.borrow_mut();
                run(code, &mut vm, &mut branches);
                if !vm.is_valid() {
                    drop(vm);
                    return Err(VerificationError::IllegalStateChange(branch));
                }
            }
            Ok(())
        }
    }
}
