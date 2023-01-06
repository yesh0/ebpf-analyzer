//! An analyzer

use core::cell::RefCell;

use alloc::{rc::Rc, vec::Vec};
use ebpf_consts::maps::MapType;

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
    /// Map type as is in [ebpf_consts::maps]
    pub map_type: MapType,
    /// Max size or fixed preallocated size
    pub max_size: u32,
    /// Size (in bytes) of the map key
    pub key_size: u32,
    /// Size (in bytes) of the map value
    pub value_size: u32,
}

/// Configuration: how the analyzer checks the code
pub struct AnalyzerConfig<'a> {
    /// Helper function calls used by the function
    ///
    /// An updating example lies here: [crate::spec::proto::helpers::HELPERS].
    pub helpers: StaticHelpers,
    /// How a [BranchState] [Vm] should be setup
    ///
    /// # Usage
    ///
    /// In order to setup the VM correctly, you will need to have an understanding
    /// of the eBPF spec, the signature of the target eBPF program
    /// (what kinds of arguments it expects), and how to represent them with this library.
    ///
    /// ## Representation
    ///
    /// We provides two representations: [crate::track::scalar::Scalar] and
    /// [crate::track::pointer::Pointer].
    ///
    /// ### Scalars
    ///
    /// Scalars are easier:
    /// - Use these methods to create constant values:
    ///   - [crate::interpreter::value::VmScalar::constant64]
    ///   - [crate::interpreter::value::VmScalar::constanti32]
    ///   - [crate::interpreter::value::VmScalar::constantu32]
    /// - Use this methods to represent an unknown value:
    ///   - [crate::track::scalar::Scalar::unknown]
    ///
    /// ### Pointers
    ///
    /// Pointers need to know about the underlying [crate::track::pointees::MemoryRegion].
    ///
    /// You will need to create a representation of that region,
    /// wrap that into a `Rc<RefCell<...>>` with probably [crate::track::pointees::pointed],
    /// and then create a pointer for it.
    ///
    /// There are two extra things:
    /// - Memory regions are resources. If some helper functions invalidates (releases)
    ///   resources, we forbid the program from using the pointers any more.
    ///   You need to use [crate::branch::vm::BranchState::add_external_resource]
    ///   or [crate::branch::vm::BranchState::add_allocated_resource] to mark every resource
    ///   the eBPF program uses.
    /// - Pointers have their own attributes: some are nullable, some are read-only or
    ///   or maybe even write-only. You may create one with
    ///   [crate::track::pointer::Pointer::nrwa] or similar methods or
    ///   [crate::track::pointer::Pointer::new] for more options.
    ///
    /// # Examples
    ///
    /// Users may inject parameters here.
    ///
    /// Imagine you want to validate a KProbes eBPF program, which accepts a context pointer
    /// as its parameter.
    ///
    /// ```
    /// use ebpf_analyzer::analyzer::AnalyzerConfig;
    /// use ebpf_analyzer::interpreter::vm::Vm;
    /// use ebpf_analyzer::track::pointer::Pointer;
    /// use ebpf_analyzer::track::pointees::pointed;
    /// use ebpf_analyzer::track::pointees::dyn_region::DynamicRegion;
    /// # const CONTEXT_STRUCT_SIZE: usize = 16;
    /// let mut config = AnalyzerConfig::default();
    ///
    /// config.setup = &|vm| {
    ///     // Create a representation of a memory region of CONTEXT_STRUCT_SIZE
    ///     let argument = pointed(DynamicRegion::new(CONTEXT_STRUCT_SIZE));
    ///     // The argument is a pointer to that region
    ///     let ptr = Pointer::nrwa(argument.clone());
    ///     // The region is always available, and never gets deallocated
    ///     vm.add_external_resource(argument);
    ///     // The argument is passed into the program via the register `R1` as per the spec
    ///     *vm.reg(1) = ptr.into();
    /// };
    /// # assert!(ebpf_analyzer::analyzer::Analyzer::analyze(&[ebpf_consts::BPF_JMP_EXIT as u64], &config).is_err());
    /// ```
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
            processed_instruction_limit: 1_000_000,
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
    pub fn analyze(code: &[u64], config: &AnalyzerConfig) -> Result<ProgramInfo, VerificationError> {
        let info = ProgramInfo::new(code)?;
        Analyzer::has_unreachable_block(&info.functions)?;
        Analyzer::has_forbidden_state_change(code, &info, config)?;
        Ok(info)
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
                if !vm.is_valid() || !vm.ro_reg(0).is_valid() {
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
