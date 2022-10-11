pub mod value;
pub mod vm;

use ebpf_consts::*;
use ebpf_macros::opcode_match;

use crate::spec::Instruction;

use self::{value::VmValue, vm::Vm};

pub fn run<Value: VmValue, M: Vm<Value>>(code: &[u64], vm: &mut M) {
    let mut pc = *vm.pc();
    while vm.is_valid() {
        let insn = Instruction::from_raw(code[pc]);
        pc += 1;
        let opcode = insn.opcode;
        opcode_match! {
            opcode,
            // ALU / ALU64: Binary operators
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
             [
                // Algebraic
                BPF_ADD: add,
                BPF_SUB: sub,
                BPF_MUL: mul,
                BPF_DIV: div,
                BPF_MOD: rem,
                // Bitwise
                BPF_AND: bitand,
                BPF_OR : bitor,
                BPF_XOR: bitxor,
                BPF_LSH: l_shift,
                BPF_RSH: r_shift,
                BPF_ARSH: signed_shr,
                // Misc
                BPF_MOV: mov,
             ]
            ] => {
                #?((K)) let src = Value::constant32(insn.imm);  ##
                #?((X)) let src = *vm.get_reg(insn.src_reg());  ##
                #?((ALU32))
                    let src = src.cast_u32();
                ##

                let dst_r = insn.dst_reg();
                #?((__mov__))
                    let dst = *vm.get_reg(dst_r);
                    #?((ALU32))
                        let dst = dst.cast_u32();
                    ##
                ##

                #?((div)|(rem))
                    let src = if src == Value::constant32(0) {
                        vm.invalidate();
                        Value::constant32(1)
                    } else {
                        src
                    };
                ##

                #?((mov))
                    let result = src;
                ##
                #?((__mov__))
                    let result = dst.#=2(src);
                ##

                vm.set_reg(dst_r, result);
            }
            // ALU / ALU64: Unary operators
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
             [
                BPF_NEG: signed_neg,
             ]
            ] => {
                let dst_r = insn.dst_reg();
                let dst = *vm.get_reg(dst_r);
                #?((ALU32))
                    let dst = dst.cast_i32();
                ##
                let result = dst.#=2();
                vm.set_reg(dst_r, result);
            }
            _ => {
                vm.invalidate();
                break;
            }
        };
        *vm.pc() = pc;
    }
}
