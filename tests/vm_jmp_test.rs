use std::{num::Wrapping, rc::Rc, cell::RefCell};

use ebpf_analyzer::interpreter::{
    run,
    vm::{UncheckedVm, Vm}, context::NoOpContext, helper::HelperCollection,
};
use ebpf_consts::*;

#[test]
pub fn test_jumps() {
    assert_jumps(BPF_JMP | BPF_JEQ | BPF_K, 0xFFFF0, 0xFFFF0, true);
    assert_jumps(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, false);
    assert_jumps(BPF_JMP | BPF_JEQ | BPF_X, 0xFFFF0, 0xFFFF0, true);
    assert_jumps(BPF_JMP | BPF_JEQ | BPF_X, 1, 0, false);

    assert_jumps(BPF_JMP | BPF_JNE | BPF_K, 0xFFFF0, 0xFFFF0, false);
    assert_jumps(BPF_JMP | BPF_JNE | BPF_K, 1, 0, true);
    assert_jumps(BPF_JMP | BPF_JNE | BPF_X, 0xFFFF0, 0xFFFF0, false);
    assert_jumps(BPF_JMP | BPF_JNE | BPF_X, 1, 0, true);

    assert_jumps(BPF_JMP32 | BPF_JEQ | BPF_K, 0xFFFF000FFFF0, 0x0000000FFFF0, true);
    assert_jumps(BPF_JMP32 | BPF_JEQ | BPF_K, 1, 0, false);
    assert_jumps(BPF_JMP32 | BPF_JEQ | BPF_X, 0xFFFF000FFFF0, 0x0000000FFFF0, true);
    assert_jumps(BPF_JMP32 | BPF_JEQ | BPF_X, 1, 0, false);

    let compares: [u8; 4] = [BPF_JGT, BPF_JGE, BPF_JLT, BPF_JLE];
    let result: [bool; 12] = [
        true, false, false,
        true, true, false,
        false, false, true,
        false, true, true,
    ];
    for (i, op) in compares.iter().enumerate() {
        assert_jumps(BPF_JMP32 | *op | BPF_X, 3, 2, result[i * 3]);
        assert_jumps(BPF_JMP32 | *op | BPF_X, 1, 1, result[i * 3 + 1]);
        assert_jumps(BPF_JMP32 | *op | BPF_X, 0, 1, result[i * 3 + 2]);
    }

    let compares: [u8; 4] = [BPF_JGT, BPF_JGE, BPF_JLT, BPF_JLE];
    let result: [bool; 12] = [
        true, false, false,
        true, true, false,
        false, false, true,
        false, true, true,
    ];
    for (i, op) in compares.iter().enumerate() {
        assert_jumps(BPF_JMP32 | *op | BPF_X, -3i64 as u64, 2, result[i * 3]);
        assert_jumps(BPF_JMP32 | *op | BPF_X, (-1i64) as u64, -1i64 as u64, result[i * 3 + 1]);
        assert_jumps(BPF_JMP32 | *op | BPF_X, -20i64 as u64, -10i64 as u64, result[i * 3 + 2]);
    }

    assert_jumps(BPF_JMP32 | BPF_JSET | BPF_X, 0xF01, 0xF001, true);
    assert_jumps(BPF_JMP32 | BPF_JSET | BPF_X, 0xF0, 0x0F, false);

    assert_jumps(BPF_JMP | BPF_JA, 0, 0, true);
    assert_jumps(BPF_JMP | BPF_EXIT, 0, 0, true);
}

pub fn assert_jumps(op: u8, dst_v: u64, src_v: u64, jumps: bool) {
    const NUMBER: u64 = 0x0EADBEEF;
    let v = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(HelperCollection::new(&[]))));
    let mut vm = v.borrow_mut();
    assert!(vm.is_valid());

    let dst = (WRITABLE_REGISTER_COUNT - 2) as u64;
    *vm.reg(dst as u8) = Wrapping(dst_v);
    let c = if (op & BPF_X) == 0 {
        op as u64 | (dst << 8) | (src_v << 32) | (1u64 << 16)
    } else {
        let src = (WRITABLE_REGISTER_COUNT - 1) as u64;
        *vm.reg(src as u8) = Wrapping(src_v);
        op as u64 | (dst << 8) | (src << 12) | (1u64 << 16)
    };

    let code = vec![
        c,
        (BPF_ALU64 | BPF_MOV | BPF_K) as u64 | (NUMBER << 32),
        0,
    ];
    run(&code, &mut vm, &mut NoOpContext{});
    assert_eq!(vm.reg(0).0, if jumps { 0 } else { NUMBER });
    if op != BPF_JMP | BPF_EXIT {
        assert!(!vm.is_valid());
        assert_eq!(*vm.pc(), 2);
    }
}
