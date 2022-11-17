use alloc::vec::Vec;

use crate::vm::context::VmContext;

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

    pub fn next(&mut self) -> Option<Branch> {
        self.branches.pop()
    }
}

impl VmContext<CheckedValue, BranchState> for BranchContext {
    fn add_pending_branch(&mut self, vm: Branch) {
        self.branches.push(vm);
    }
}
