use std::{num::Wrapping, rc::Rc, cell::RefCell};

use ebpf_analyzer::interpreter::{
    run,
    vm::{UncheckedVm, Vm}, context::NoOpContext, helper::HelperCollection,
};
use ebpf_consts::{
    mask::BPF_OPCODE_CLASS_MASK, BPF_DW, BPF_LDX, BPF_MEM, BPF_ST, BPF_STX, STACK_REGISTER, BPF_W, BPF_H, BPF_B, BPF_LD, BPF_IMM,
};

#[test]
pub fn test_store_load() {
    assert_store_load(
        BPF_STX | BPF_MEM | BPF_DW,
        0xFFFF0000FFFF0000,
        0xFFFF0000FFFF0000,
    );
    assert_store_load(
        BPF_LDX | BPF_MEM | BPF_DW,
        0xFFFF0000FFFF0000,
        0xFFFF0000FFFF0000,
    );
    assert_store_load(
        BPF_ST | BPF_MEM | BPF_DW,
        0xFFFF0000FFFF0000,
        0x00000000FFFF0000,
    );
    for op in [BPF_ST, BPF_STX, BPF_LDX] {
        assert_store_load(
            op | BPF_MEM | BPF_W,
            0xFFFF0000FFFF0000,
            0x00000000FFFF0000u64.to_le(),
        );
        assert_store_load(
            op | BPF_MEM | BPF_H,
            0xFFFF0000FFFF00FF,
            0x00000000000000FFu64.to_le(),
        );
        assert_store_load(
            op | BPF_MEM | BPF_B,
            0xFFFF0000FFFF00FF,
            0x00000000000000FFu64.to_le(),
        );
    }
}

#[test]
pub fn test_imm64() {
    let v = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(HelperCollection::new(&[]))));
    let mut vm = v.borrow_mut();
    assert!(vm.is_valid());

    let code = [
        (BPF_LD | BPF_IMM | BPF_DW) as u64 | (0xDEADBEEFu64 << 32),
        (0xCAFEBABEu64 << 32),
        0,
    ];
    run(&code, &mut vm, &mut NoOpContext{});
    assert_eq!(vm.reg(0).0, 0xCAFE_BABE_DEAD_BEEF_u64);
    assert_eq!(*vm.pc(), 2);
}

pub fn assert_store_load(op: u8, value: u64, result: u64) {
    let v = Rc::new(RefCell::new(UncheckedVm::<Wrapping<u64>>::new(HelperCollection::new(&[]))));
    let mut vm = v.borrow_mut();
    assert!(vm.is_valid());

    let stack = STACK_REGISTER as u64;
    let src = 0u64;

    let offset = (-8i16 as u16 as u64) << 16;
    let c = match op & BPF_OPCODE_CLASS_MASK {
        BPF_STX => {
            *vm.reg(src as u8) = Wrapping(value);
            op as u64 | (stack << 8) | (src << 12) | offset
        }
        BPF_ST => op as u64 | (stack << 8) | offset | (value << 32),
        BPF_LDX => {
            unsafe { *((vm.ro_reg(STACK_REGISTER).0 - 8) as *mut u64) = value; }
            op as u64 | (src << 8) | (stack << 12) | offset
        }
        _ => panic!("Invalid opcode"),
    };
    let code = [c, 0];
    run(&code, &mut vm, &mut NoOpContext{});
    assert!(!vm.is_valid());
    assert_eq!(*vm.pc(), 1);
    if op & BPF_OPCODE_CLASS_MASK == BPF_LDX {
        assert_eq!(vm.reg(src as u8).0, result);
    } else {
        let v = unsafe { *((vm.ro_reg(STACK_REGISTER).0 - 8) as *mut u64) };
        assert_eq!(v, result);
    }
}
