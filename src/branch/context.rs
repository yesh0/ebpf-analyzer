use alloc::vec::Vec;

use crate::interpreter::context::VmContext;

use super::{
    checked_value::CheckedValue,
    vm::{Branch, BranchState},
};

pub struct BranchContext {
    branches: Vec<Branch>,
}

impl BranchContext {
    pub fn new() -> BranchContext {
        BranchContext {
            branches: Vec::new(),
        }
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

impl VmContext<CheckedValue, BranchState> for BranchContext {
    fn add_pending_branch(&mut self, vm: Branch) {
        self.branches.push(vm);
    }
}
