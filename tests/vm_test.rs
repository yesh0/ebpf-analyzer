use std::num::Wrapping;

use ebpf_analyzer::vm::{
    run,
    vm::{UncheckedVm, Vm},
};
use ebpf_consts::{
    BPF_ADD, BPF_ALU, BPF_ALU64, BPF_DIV, BPF_K, BPF_MOD, BPF_MUL, BPF_SUB, BPF_X,
    WRITABLE_REGISTER_COUNT, BPF_NEG, BPF_MOV, BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH, BPF_ARSH,
};

#[test]
pub fn test_algebra() {
    assert_biop(BPF_ALU64 | BPF_ADD | BPF_X, 0, 0, 0);
    assert_biop(
        BPF_ALU64 | BPF_ADD | BPF_X,
        0xFFFF0000,
        0x0000FFFF,
        0xFFFFFFFF,
    );
    assert_biop(
        BPF_ALU64 | BPF_ADD | BPF_X,
        0xFFFF00000000,
        0x0000FFFF0000,
        0xFFFFFFFF0000,
    );
    assert_biop(
        BPF_ALU | BPF_ADD | BPF_X,
        0xFFFF00000000,
        0x0000FFFF0000,
        0xFFFF0000,
    );
    assert_biop(
        BPF_ALU | BPF_ADD | BPF_K,
        0xFFFF00000000,
        0x0000FFFF0000,
        0xFFFF0000,
    );

    assert_biop(
        BPF_ALU64 | BPF_SUB | BPF_X,
        0xFFFF00000000,
        0x0000FFFF0000,
        0xFFFE00010000,
    );
    assert_biop(
        BPF_ALU64 | BPF_SUB | BPF_X,
        0x0000FFFF0000,
        0xFFFF00000000,
        0xFFFF0001FFFF0000,
    );
    assert_biop(BPF_ALU | BPF_SUB | BPF_X, 0xFFFFF0000000, 0x0000F0000000, 0);
    assert_biop(BPF_ALU | BPF_SUB | BPF_K, 0xFFFFF0000000, 0x0000F0000000, 0);

    assert_biop(
        BPF_ALU64 | BPF_MUL | BPF_X,
        0x10000000,
        0x1000,
        0x10000000000,
    );
    assert_biop(BPF_ALU | BPF_MUL | BPF_X, 0x1000, 0x1000, 0x1000000);
    assert_biop(BPF_ALU | BPF_MUL | BPF_K, 0x1000, 0x1000, 0x1000000);

    assert_biop(BPF_ALU64 | BPF_DIV | BPF_X, 0x10000000, 0x1000, 0x10000);
    assert_biop(BPF_ALU | BPF_DIV | BPF_X, 0x1000, 0x1000, 0x1);
    assert_biop(BPF_ALU | BPF_DIV | BPF_K, 0x1000, 0x1000, 0x1);
    assert_biop(BPF_ALU64 | BPF_DIV | BPF_X, 0x10000010, 0x1000, 0x10000);
    assert_biop(BPF_ALU | BPF_DIV | BPF_X, 0x1010, 0x1000, 0x1);
    assert_biop(BPF_ALU | BPF_DIV | BPF_K, 0x1010, 0x1000, 0x1);

    assert_biop(BPF_ALU64 | BPF_MOD | BPF_X, 0x10000000, 0x1000, 0);
    assert_biop(BPF_ALU | BPF_MOD | BPF_X, 0x1000, 0x1000, 0);
    assert_biop(BPF_ALU | BPF_MOD | BPF_K, 0x1000, 0x1000, 0);
    assert_biop(BPF_ALU64 | BPF_MOD | BPF_X, 0x10000010, 0x1000, 0x10);
    assert_biop(BPF_ALU | BPF_MOD | BPF_X, 0x1010, 0x1000, 0x10);
    assert_biop(BPF_ALU | BPF_MOD | BPF_K, 0x1010, 0x1000, 0x10);

    assert_biop(BPF_ALU64 | BPF_NEG | BPF_X, 0x1, 0, 0xFFFFFFFFFFFFFFFF);
    assert_biop(BPF_ALU | BPF_NEG | BPF_X, 0x1, 0, 0xFFFFFFFFFFFFFFFF);
    assert_biop(BPF_ALU64 | BPF_NEG | BPF_K, 0x1, 0, 0xFFFFFFFFFFFFFFFF);
    assert_biop(BPF_ALU | BPF_NEG | BPF_K, 0x1, 0, 0xFFFFFFFFFFFFFFFF);

    assert_biop(BPF_ALU64 | BPF_MOV | BPF_X, 0x1, 0xFFFFFFFF, 0xFFFFFFFF);
    assert_biop(BPF_ALU | BPF_MOV | BPF_X, 0x1, 0xFFFFFFFFFFFF, 0xFFFFFFFF);
    assert_biop(BPF_ALU | BPF_MOV | BPF_K, 0x1, 0xFFFFFFFFFFFFF, 0xFFFFFFFF);
    assert_biop(BPF_ALU64 | BPF_MOV | BPF_K, 0x1, 0xF0F000000, 0x0F000000);
}

#[test]
pub fn test_bitwise() {
    assert_biop(BPF_ALU64 | BPF_AND | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0xFFFF0000000F);
    assert_biop(BPF_ALU | BPF_AND | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0000000F);
    assert_biop(BPF_ALU64 | BPF_AND | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0000000F);
    assert_biop(BPF_ALU | BPF_AND | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0000000F);

    assert_biop(BPF_ALU64 | BPF_OR | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0xFFFF0FFFFFFF);
    assert_biop(BPF_ALU | BPF_OR | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0FFFFFFF);
    assert_biop(BPF_ALU64 | BPF_OR | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0xFFFF0FFFFFFF);
    assert_biop(BPF_ALU | BPF_OR | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0FFFFFFF);

    assert_biop(BPF_ALU64 | BPF_XOR | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0FFFFFF0);
    assert_biop(BPF_ALU | BPF_XOR | BPF_X, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0FFFFFF0);
    assert_biop(BPF_ALU64 | BPF_XOR | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0xFFFF0FFFFFF0);
    assert_biop(BPF_ALU | BPF_XOR | BPF_K, 0xFFFF0FFF000F, 0xFFFF0000FFFF, 0x0FFFFFF0);

    assert_biop(BPF_ALU64 | BPF_RSH | BPF_K, 0x100000000, 32, 1);
    assert_biop(BPF_ALU64 | BPF_LSH | BPF_K, 1, 32, 0x100000000);
    assert_biop(BPF_ALU | BPF_ARSH | BPF_K, 0xF0000000, 28, 0xFFFFFFFF);
    assert_biop(BPF_ALU64 | BPF_ARSH | BPF_K, 0xF000000000000000, 28, 0xFFFFFFFF00000000);
}

pub fn assert_biop(op: u8, dst_v: u64, src_v: u64, result: u64) {
    let mut vm = UncheckedVm::<Wrapping<u64>>::new();
    assert!(vm.is_valid());
    let dst = (WRITABLE_REGISTER_COUNT - 2) as u64;
    vm.set_reg(dst as u8, Wrapping(dst_v));
    let c = if (BPF_X & op) == 0 {
        op as u64 | (dst << 8) | (src_v << 32)
    } else {
        let src = (WRITABLE_REGISTER_COUNT - 1) as u64;
        vm.set_reg(src as u8, Wrapping(src_v));
        op as u64 | (src << 12) | (dst << 8)
    };
    let code = vec![c, 0];
    run(&code, &mut vm);
    assert_eq!(vm.get_reg(dst as u8).0, result);
}
