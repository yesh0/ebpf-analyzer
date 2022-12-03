use std::{num::Wrapping, rc::Rc, cell::RefCell};

use ebpf_analyzer::interpreter::{
    run,
    vm::{UncheckedVm, Vm}, context::NoOpContext, helper::HelperCollection,
};
use ebpf_consts::{
    BPF_ATOMIC, BPF_ATOMIC_ADD, BPF_ATOMIC_AND, BPF_ATOMIC_CMPXCHG, BPF_ATOMIC_FETCH,
    BPF_ATOMIC_OR, BPF_ATOMIC_XCHG, BPF_ATOMIC_XOR, BPF_DW, BPF_STX, STACK_REGISTER,
};

#[test]
pub fn test_atomic() {
    assert_atomic(BPF_ATOMIC_ADD, 0, 0xFF00, 0x0FF0, 0x10EF0, 0xFF00);
    assert_atomic(
        BPF_ATOMIC_ADD | BPF_ATOMIC_FETCH,
        0,
        0xFF00,
        0x0FF0,
        0x10EF0,
        0x0FF0,
    );

    assert_atomic(BPF_ATOMIC_OR, 0, 0xFF00, 0x0FF0, 0xFFF0, 0xFF00);
    assert_atomic(
        BPF_ATOMIC_OR | BPF_ATOMIC_FETCH,
        0,
        0xFF00,
        0x0FF0,
        0xFFF0,
        0x0FF0,
    );

    assert_atomic(BPF_ATOMIC_AND, 0, 0xFF00, 0x0FF0, 0x0F00, 0xFF00);
    assert_atomic(
        BPF_ATOMIC_AND | BPF_ATOMIC_FETCH,
        0,
        0xFF00,
        0x0FF0,
        0x0F00,
        0x0FF0,
    );

    assert_atomic(BPF_ATOMIC_XOR, 0, 0xFF00, 0x0FF0, 0xF0F0, 0xFF00);
    assert_atomic(
        BPF_ATOMIC_XOR | BPF_ATOMIC_FETCH,
        0,
        0xFF00,
        0x0FF0,
        0xF0F0,
        0x0FF0,
    );

    assert_atomic(BPF_ATOMIC_XCHG, 0, 0xFF00, 0x0FF0, 0xFF00, 0x0FF0);

    assert_atomic(BPF_ATOMIC_CMPXCHG, 0x0FF0, 0xFF00, 0x0FF0, 0xFF00, 0x0FF0);
    assert_atomic(BPF_ATOMIC_CMPXCHG, 0x0000, 0xFF00, 0x0FF0, 0x0FF0, 0x0FF0);
}

pub fn assert_atomic(imm: i32, r0: u64, src_v: u64, target: u64, expected: u64, returns: u64) {
    let v = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(HelperCollection::new(&[]))));
    let mut vm = v.borrow_mut();
    assert!(vm.is_valid());

    let stack = STACK_REGISTER as u64;
    let src = 1u64;

    *vm.reg(0) = Wrapping(r0);
    *vm.reg(src as u8) = Wrapping(src_v);
    unsafe {
        *((vm.ro_reg(STACK_REGISTER).0 - 8) as *mut u64) = target;
    }
    let v = unsafe { *((vm.ro_reg(STACK_REGISTER).0 - 8) as *mut u64) };
    assert!(v == target);

    let opcode = BPF_STX | BPF_ATOMIC | BPF_DW;
    let offset = (-8i16 as u16 as u64) << 16;
    let regs = ((src << 4) | stack) << 8;
    let c = opcode as u64 | regs | offset | ((imm as u64) << 32);
    let code = [c, 0];
    run(&code, &mut vm, &mut NoOpContext{});
    assert!(!vm.is_valid());
    assert_eq!(*vm.pc(), 2);

    let v = unsafe { *((vm.ro_reg(STACK_REGISTER).0 - 8) as *mut u64) };
    assert_eq!(v, expected);
    if imm == BPF_ATOMIC_CMPXCHG {
        assert_eq!(vm.ro_reg(0).0, returns);
    } else {
        assert_eq!(vm.ro_reg(src as u8).0, returns);
    }
}
