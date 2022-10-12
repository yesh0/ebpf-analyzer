pub mod value;
pub mod vm;

use core::cmp::Ordering::*;

use ebpf_consts::*;
use ebpf_macros::opcode_match;

use crate::spec::Instruction;

use self::{value::VmValue, vm::{Vm, BranchTracker}};

/// Runs (or, interprets) the code on the given VM
pub fn run<Value: VmValue, M: Vm<Value>, T: BranchTracker>(code: &[u64], vm: &mut M, tracker: &mut T) {
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
                // Gettings the src operant
                #?((K)) let src = Value::constant32(insn.imm);  ##
                #?((X)) let src = *vm.get_reg(insn.src_reg());  ##
                #?((ALU32))
                    let src = src.cast_u32();
                ##

                // Gettings the dst operant
                let dst_r = insn.dst_reg();
                #?((__mov__))
                    let dst = *vm.get_reg(dst_r);
                    #?((ALU32))
                        #?((signed_shr))
                            let dst = dst.cast_i32();
                        ##
                        #?((__signed_shr__))
                            let dst = dst.cast_u32();
                        ##
                    ##
                ##

                #?((div)|(rem))
                    if src == Value::constant32(0) {
                        vm.invalidate();
                        break;
                    }
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
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_K: K],
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
            // ALU / ALU64: Byte swap
            [[BPF_ALU: ALU32], [BPF_END: END],
             [
                BPF_TO_LE: host_to_le,
                BPF_TO_BE: host_to_be,
             ]
            ] => {
                let dst_r = insn.dst_reg();
                let dst = *vm.get_reg(dst_r);
                let result = dst.#=2(insn.imm);
                vm.set_reg(dst_r, result);
            }
            // JMP32 / JMP: Conditional
            [[BPF_JMP32: JMP32, BPF_JMP: JMP64], [BPF_X: X, BPF_K: K],
             [
                // Unsigned
                BPF_JEQ: "[Equal]",
                BPF_JNE: "[Greater, Less]",
                BPF_JGT: "[Greater]",
                BPF_JGE: "[Greater, Equal]",
                BPF_JLT: "[Less]",
                BPF_JLE: "[Less, Equal]",
                // Signed
                BPF_JSGT: "[Greater]",
                BPF_JSGE: "[Greater, Equal]",
                BPF_JSLT: "[Less]",
                BPF_JSLE: "[Less, Equal]",
                // Misc
                BPF_JSET: "[Less, Greater]",
             ]
            ] => {
                let dst = *vm.get_reg(insn.dst_reg());
                #?((K)) let src = Value::constant32(insn.imm);  ##
                #?((X)) let src = *vm.get_reg(insn.src_reg());  ##

                // Casting
                #?((JMP32))
                    #?((BPF_JSGT)|(BPF_JSGE)|(BPF_JSLT)|(BPF_JSLE))
                        let dst = dst.cast_i32();
                        let src = src.cast_i32();
                    ##
                    #?((__BPF_JSGT__,__BPF_JSGE__,__BPF_JSLT__,__BPF_JSLE__))
                        let dst = dst.cast_u32();
                        let src = src.cast_u32();
                    ##
                ##

                // Comparison
                #?((__BPF_JSGT__,__BPF_JSGE__,__BPF_JSLT__,__BPF_JSLE__,__BPF_JSET__))
                    let result = dst.partial_cmp(&src);
                ##
                #?((BPF_JSGT)|(BPF_JSGE)|(BPF_JSLT)|(BPF_JSLE))
                    let result = dst.signed_partial_cmp(&src);
                ##
                #?((BPF_JSET))
                    let result = dst.bitand(src).partial_cmp(&Value::constant32(0));
                ##

                let allowed = #=2;
                let target = if insn.off >= 0 {
                    pc + (insn.off as usize)
                } else {
                    pc - ((-insn.off) as usize)
                };
                if tracker.conditional_jump(&result, &allowed, target) {
                    break;
                }
                if let Some(cmp) = result {
                    if allowed.contains(&cmp) {
                        pc = target;
                    }
                } else {
                    vm.invalidate();
                }
            }
            // BPF_JA: Unconditional jump
            [[BPF_JMP: JMP], [BPF_JA: JA]] => {
                if insn.off >= 0 {
                    pc += insn.off as usize;
                } else {
                    pc -= (-insn.off) as usize;
                }
                if tracker.jump_to(pc) {
                    break;
                }
            }
            // BPF_EXIT: Exits
            [[BPF_JMP: JMP], [BPF_EXIT: EXIT]] => {
                tracker.exit();
                break;
            }
            // TODO: BPF_CALL
            // Store / load
            [[BPF_LDX: LDX, BPF_STX: STX, BPF_ST: ST], [BPF_MEM: MEM],
             [
                BPF_B: "8",
                BPF_H: "16",
                BPF_W: "32",
                BPF_DW: "64",
             ]
            ] => {
                const SIZE: usize = #=2;
                #?((LDX))
                    let src = *vm.get_reg(insn.src_reg());
                    if let Some(value) = unsafe { src.get_at(insn.off, SIZE) } {
                        vm.set_reg(insn.dst_reg(), value);
                    } else {
                        vm.invalidate();
                    }
                ##
                #?((STX))
                    let dst = *vm.get_reg(insn.dst_reg());
                    let src = *vm.get_reg(insn.src_reg());
                    unsafe {
                        if !dst.set_at(insn.off, SIZE, src) {
                            vm.invalidate();
                        }
                    }
                ##
                #?((ST))
                    let dst = *vm.get_reg(insn.dst_reg());
                    unsafe {
                        if !dst.set_at(insn.off, SIZE, Value::constant64(insn.imm as u32 as u64)) {
                            vm.invalidate();
                        }
                    }
                ##
            }
            [[BPF_LD: LD], [BPF_IMM: IMM], [BPF_DW: DW]] => {
                let value = insn.imm as u32 as u64 | (code[pc] & 0xFFFF_FFFF_0000_0000);
                vm.set_reg(insn.dst_reg(), Value::constant64(value));
                pc += 1;
            }
            #[cfg(feature = "atomic32")]
            [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_W: W]] => {
                run_atomic(insn, vm, 32);
            }
            #[cfg(feature = "atomic64")]
            [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_DW: DW]] => {
                run_atomic(insn, vm, 64);
            }
            _ => {
                vm.invalidate();
                break;
            }
        };
        *vm.pc() = pc;
    }
}

fn run_atomic<Value: VmValue, M: Vm<Value>>(insn: Instruction, vm: &mut M, size: usize) {
    let atomic_code = insn.imm as i32;
    opcode_match! {
        atomic_code as i32,
        [[BPF_ATOMIC_FETCH: FETCH, BPF_ATOMIC_NO_FETCH: NO_FETCH],
         [
            BPF_ATOMIC_ADD: "fetch_add",
            BPF_ATOMIC_OR : "fetch_or",
            BPF_ATOMIC_AND: "fetch_and",
            BPF_ATOMIC_XOR: "fetch_xor",
         ]
        ] => {
            let src_r =  insn.src_reg();
            let dst = *vm.get_reg(insn.dst_reg());
            let src = *vm.get_reg(src_r);
            let result = dst.#=1(insn.off, src, size);
            if let None = result {
                vm.invalidate();
                return;
            }
            #?((FETCH))
                if let Some(old) = result {
                    vm.set_reg(src_r, old);
                }
            ##
        }
        [[BPF_ATOMIC_FETCH: FETCH], [BPF_ATOMIC_XCHG: XCHG]] => {
            let src_r =  insn.src_reg();
            let dst = *vm.get_reg(insn.dst_reg());
            let src = *vm.get_reg(src_r);
            if let Some(old) = dst.swap(insn.off, src, size) {
                vm.set_reg(src_r, old);
            } else {
                vm.invalidate();
            }
        }
        [[BPF_ATOMIC_FETCH: FETCH], [BPF_ATOMIC_CMPXCHG: CMPXCHG]] => {
            let src_r =  insn.src_reg();
            let dst = *vm.get_reg(insn.dst_reg());
            let src = *vm.get_reg(src_r);
            let expected = *vm.get_reg(0);
            if let Some(old) = dst.compare_exchange(insn.off, expected, src, size) {
                vm.set_reg(0, old);
            } else {
                vm.invalidate();
            }
        }
        _ => vm.invalidate(),
    };
}
