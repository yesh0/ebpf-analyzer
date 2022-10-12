use std::num::Wrapping;

use ebpf_analyzer::vm::{
    run,
    vm::{UncheckedVm, Vm},
};
use ebpf_consts::{
    BPF_DW, BPF_STX, STACK_REGISTER, BPF_ATOMIC, BPF_ATOMIC_CMPXCHG, BPF_ATOMIC_ADD, BPF_ATOMIC_FETCH, BPF_ATOMIC_OR, BPF_ATOMIC_AND, BPF_ATOMIC_XOR, BPF_ATOMIC_XCHG,
};

#[test]
pub fn test_atomic() {
    assert_atomic(BPF_ATOMIC_ADD, 0, 0xFF00, 0x0FF0, 0x10EF0, 0xFF00);
    assert_atomic(BPF_ATOMIC_ADD | BPF_ATOMIC_FETCH, 0, 0xFF00, 0x0FF0, 0x10EF0, 0x0FF0);

    assert_atomic(BPF_ATOMIC_OR, 0, 0xFF00, 0x0FF0, 0xFFF0, 0xFF00);
    assert_atomic(BPF_ATOMIC_OR | BPF_ATOMIC_FETCH, 0, 0xFF00, 0x0FF0, 0xFFF0, 0x0FF0);

    assert_atomic(BPF_ATOMIC_AND, 0, 0xFF00, 0x0FF0, 0x0F00, 0xFF00);
    assert_atomic(BPF_ATOMIC_AND | BPF_ATOMIC_FETCH, 0, 0xFF00, 0x0FF0, 0x0F00, 0x0FF0);

    assert_atomic(BPF_ATOMIC_XOR, 0, 0xFF00, 0x0FF0, 0xF0F0, 0xFF00);
    assert_atomic(BPF_ATOMIC_XOR | BPF_ATOMIC_FETCH, 0, 0xFF00, 0x0FF0, 0xF0F0, 0x0FF0);

    assert_atomic(BPF_ATOMIC_XCHG, 0, 0xFF00, 0x0FF0, 0xFF00, 0x0FF0);

    assert_atomic(BPF_ATOMIC_CMPXCHG, 0x0FF0, 0xFF00, 0x0FF0, 0xFF00, 0x0FF0);
    assert_atomic(BPF_ATOMIC_CMPXCHG, 0x0000, 0xFF00, 0x0FF0, 0x0FF0, 0x0FF0);
}

pub fn assert_atomic(imm: i32, r0: u64, src_v: u64, target: u64, expected: u64, returns: u64) {
    let mut vm = UncheckedVm::<Wrapping<u64>>::new();
    assert!(vm.is_valid());

    let stack = STACK_REGISTER as u64;
    let src = 8u64;

    vm.set_reg(0, Wrapping(r0));
    vm.set_reg(src as u8, Wrapping(src_v));
    vm.set_stack(1, Wrapping(target));

    let opcode = BPF_STX | BPF_ATOMIC | BPF_DW;
    let offset = 8u64 << 16;
    let regs = ((src << 4) | stack) << 8;
    let c = opcode as u64 | regs | offset | ((imm as u64) << 32);
    let code = [c, 0];
    run(&code, &mut vm);
    assert!(!vm.is_valid());
    assert_eq!(*vm.pc(), 1);

    assert_eq!(vm.get_stack(1).0, expected);
    if imm == BPF_ATOMIC_CMPXCHG {
        assert_eq!(vm.get_reg(0).0, returns);
    } else {
        assert_eq!(vm.get_reg(src as u8).0, returns);
    }
}
