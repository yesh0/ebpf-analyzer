use std::num::Wrapping;

use ebpf_analyzer::vm::{
    run,
    vm::{UncheckedVm, Vm},
};
use ebpf_consts::{
    mask::BPF_OPCODE_CLASS_MASK, BPF_DW, BPF_LDX, BPF_MEM, BPF_ST, BPF_STX, STACK_REGISTER, BPF_W, BPF_H, BPF_B,
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

pub fn assert_store_load(op: u8, value: u64, result: u64) {
    let mut vm = UncheckedVm::<Wrapping<u64>>::new();
    assert!(vm.is_valid());

    let stack = STACK_REGISTER as u64;
    let src = 0u64;

    let offset = 8u64 << 16;
    let c = match op & BPF_OPCODE_CLASS_MASK {
        BPF_STX => {
            vm.set_reg(src as u8, Wrapping(value));
            op as u64 | (stack << 8) | (src << 12) | offset
        }
        BPF_ST => op as u64 | (stack << 8) | offset | (value << 32),
        BPF_LDX => {
            vm.set_stack(1, Wrapping(value));
            op as u64 | (src << 8) | (stack << 12) | offset
        }
        _ => panic!("Invalid opcode"),
    };
    let code = [c, 0];
    run(&code, &mut vm);
    assert!(!vm.is_valid());
    assert_eq!(*vm.pc(), 1);
    if op & BPF_OPCODE_CLASS_MASK == BPF_LDX {
        assert_eq!(vm.get_reg(src as u8).0, result);
    } else {
        assert_eq!(vm.get_stack(1).0, result);
    }
}
