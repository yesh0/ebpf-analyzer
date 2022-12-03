//! See [BranchContext] and [VmContext].

use alloc::vec::Vec;

use crate::interpreter::{context::VmContext, value::Verifiable};

use super::{
    checked_value::CheckedValue,
    vm::{Branch, BranchState},
};

/// A simple context collecting all unexplored branches
pub struct BranchContext {
    branches: Vec<Branch>,
    instruction_count: usize,
    instruction_limit: usize,
    invalid: Option<&'static str>,
}

impl BranchContext {
    /// Creates an empty context
    pub fn new() -> BranchContext {
        BranchContext {
            branches: Vec::new(),
            instruction_count: 0,
            instruction_limit: 1000000,
            invalid: None,
        }
    }

    /// Returns the invalidation cause
    pub fn invalid_message(&self) -> &'static str {
        self.invalid.unwrap_or("Unknown cause")
    }

    /// Sets an limit for total processed instructions
    pub fn set_instruction_limit(&mut self, limit: usize) {
        self.instruction_limit = limit;
    }
}

impl Default for BranchContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for BranchContext {
    type Item = Branch;

    fn next(&mut self) -> Option<Self::Item> {
        self.branches.pop()
    }
}

impl Verifiable for BranchContext {
    fn is_valid(&self) -> bool {
        self.invalid.is_none()
    }
}

impl VmContext<CheckedValue, BranchState> for BranchContext {
    fn add_pending_branch(&mut self, vm: Branch) {
        self.branches.push(vm);
    }

    fn increment_pc(&mut self) {
        self.instruction_count += 1;
        if self.instruction_count >= self.instruction_limit {
            self.invalid = Some("Too many instructions to process");
        }
    }
}
