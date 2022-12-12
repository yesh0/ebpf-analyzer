//! An analyzer

use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};

use crate::{
    blocks::{FunctionBlocks, IllegalStructure, ProgramInfo, TERMINAL_PSEUDO_BLOCK},
    branch::{
        context::BranchContext,
        vm::{Branch, BranchState, StaticHelpers},
    },
    interpreter::{context::VmContext, run, value::Verifiable, vm::Vm},
    spec::IllegalInstruction,
};

/// eBPF map info
pub struct MapInfo {
    /// Size (in bytes) of the map key
    pub key_size: u32,
    /// Size (in bytes) of the map value
    pub value_size: u32,
}

/// Configuration: how the analyzer checks the code
pub struct AnalyzerConfig<'a> {
    /// Helper function calls used by the function
    pub helpers: StaticHelpers,
    /// How a VM should be setup
    ///
    /// Users may inject parameters here.
    pub setup: &'a dyn Fn(&mut BranchState),
    /// Maximum processable instruction count
    ///
    /// The verifier goes through each possible branch, looking for invalid operations.
    /// This setting limits total processed instruction, summing up all the processed branches.
    pub processed_instruction_limit: usize,
    /// Gets map file descriptor info
    pub map_fd_collector: &'a dyn Fn(i32) -> Option<MapInfo>,
}

impl<'a> Default for AnalyzerConfig<'a> {
    fn default() -> Self {
        Self {
            helpers: Default::default(),
            setup: &|_| {},
            processed_instruction_limit: Default::default(),
            map_fd_collector: &|_| None,
        }
    }
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
    /// Illegal context
    IllegalContext(&'static str),
}

impl From<IllegalInstruction> for VerificationError {
    fn from(err: IllegalInstruction) -> Self {
        Self::IllegalInstruction(err)
    }
}

impl Analyzer {
    /// Analyze an eBPF program
    pub fn analyze(code: &[u64], config: &AnalyzerConfig) -> Result<usize, VerificationError> {
        let info = ProgramInfo::new(code)?;
        Analyzer::has_unreachable_block(&info.functions)?;
        Analyzer::has_forbidden_state_change(code, &info, config)?;
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
        info: &ProgramInfo,
        config: &AnalyzerConfig,
    ) -> Result<(), VerificationError> {
        if info.functions.is_empty() {
            Err(VerificationError::IllegalStructure(IllegalStructure::Empty))
        } else {
            let mut maps: Vec<(i32, MapInfo)> = Vec::new();
            maps.reserve(info.maps.len());
            for fd in &info.maps {
                if let Some(map) = (config.map_fd_collector)(*fd) {
                    maps.push((*fd, map));
                } else {
                    return Err(VerificationError::IllegalInstruction(
                        IllegalInstruction::MapFdNotAvailable,
                    ));
                }
            }

            let mut branches = BranchContext::new();
            branches.set_instruction_limit(config.processed_instruction_limit);
            let mut branch = BranchState::new(config.helpers, maps);
            (config.setup)(&mut branch);
            branches.add_pending_branch(Rc::new(RefCell::new(branch)));
            while let Some(branch) = branches.next() {
                let mut vm = branch.borrow_mut();
                run(code, &mut vm, &mut branches);
                if !vm.is_valid() {
                    drop(vm);
                    return Err(VerificationError::IllegalStateChange(branch));
                }
                if !branches.is_valid() {
                    return Err(VerificationError::IllegalContext(
                        branches.invalid_message(),
                    ));
                }
            }
            Ok(())
        }
    }
}
