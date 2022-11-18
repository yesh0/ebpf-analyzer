use std::{cell::RefCell, num::Wrapping, rc::Rc};

use ebpf_analyzer::interpreter::{
    self,
    context::NoOpContext,
    helper::HelperCollection,
    vm::{UncheckedVm, Vm},
};
use llvm_util::{helper, parse_llvm_dump};

pub const HELPER_USAGE: &str = include_str!("bpf-src/helper-test.txt");

static mut VARIABLE: u64 = 0;

#[test]
fn test_helper_call() {
    let code = parse_llvm_dump(HELPER_USAGE);
    let vm = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(
        HelperCollection::new(&[helper::nop, helper::as_is, |i, _, _, _, _| {
            unsafe {
                VARIABLE = i;
            }
            i
        }]),
    )));
    interpreter::run(&code, &mut vm.borrow_mut(), &mut NoOpContext::default());
    assert!(vm.borrow_mut().is_valid());
    assert!((unsafe { VARIABLE } as u8 as char).is_alphabetic());
}
