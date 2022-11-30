//! Implements a generic interpreter and a tiny VM.
//!
//! The interpreter is designed to run eBPF intructions
//! on a virtual [Vm], backed by a value implementation [VmValue],
//! which can get transparently replaced from [u64] with
//! a value type with verification purposes like [crate::branch::checked_value::CheckedValue].
//!
//! It also heavily uses the [opcode_match] macro, which messes around the code pieces.

pub mod context;
pub mod helper;
pub mod value;
pub mod vm;

use core::cell::RefMut;

use ebpf_consts::*;
use ebpf_macros::opcode_match;

use crate::{interpreter::context::Fork, spec::Instruction};

use self::{context::VmContext, value::VmValue, vm::Vm};

macro_rules! break_if_none {
    ($value:expr) => {
        if let Some(v) = $value {
            v
        } else {
            break;
        }
    };
}
macro_rules! return_if_none {
    ($value:expr) => {
        if let Some(v) = $value {
            v
        } else {
            return;
        }
    };
}

/// Runs (or, interprets) the code on the given VM
pub fn run<Value: VmValue, M: Vm<Value>, C: VmContext<Value, M>>(
    code: &[u64],
    vm: &mut RefMut<M>,
    context: &mut C,
) {
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
                BPF_ADD: add_assign,
                BPF_SUB: sub_assign,
                BPF_MUL: mul_assign,
                BPF_DIV: div_assign,
                BPF_MOD: rem_assign,
                // Bitwise
                BPF_AND: bitand_assign,
                BPF_OR : bitor_assign,
                BPF_XOR: bitxor_assign,
             ]
            ] => {
                // Gettings the dst operant
                let dst_r = insn.dst_reg();
                // Gettings the src operant
                #?((K))
                    #?((ALU32))
                        let src = &mut Value::constantu32(insn.imm as u32);
                    ##
                    #?((ALU64))
                        let src = &mut Value::constanti32(insn.imm);
                    ##
                    let dst = vm.reg(dst_r);
                ##
                #?((X))
                    let (dst, src) = break_if_none!(vm.two_regs(dst_r, insn.src_reg()));
                ##
                #?((ALU32))
                    let src = &src.lower_half();
                ##

                #?((ALU32))
                    dst.lower_half_assign();
                ##

                #?((div_assign,K)|(rem_assign,K))
                    if insn.imm == 0 {
                        vm.invalidate("Div by 0");
                        break;
                    }
                ##

                dst.#=2(src);
                #?((ALU32))
                    dst.lower_half_assign();
                ##
                vm.update_reg(dst_r);
            }
            // BPF_ALU_MOV: Sign extending for BPF_K
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
             [BPF_MOV: mov]
            ] => {
                let dst_r = insn.dst_reg();
                #?((K))
                    #?((ALU32))
                        let src = &mut Value::constantu32(insn.imm as u32);
                    ##
                    #?((ALU64))
                        let src = &mut Value::constanti32(insn.imm);
                    ##
                    let dst = vm.reg(dst_r);
                ##
                #?((X))
                    let (dst, src) = break_if_none!(vm.two_regs(dst_r, insn.src_reg()));
                ##

                *dst = src.clone();

                #?((ALU32))
                    dst.zero_upper_half_assign();
                ##
                vm.update_reg(dst_r);
            }
            // Shifts: Width aware
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
             [
                BPF_LSH: l_shift,
                BPF_RSH: r_shift,
                BPF_ARSH: signed_shr
             ]
            ] => {
                // Gettings the dst operant
                let dst_r = insn.dst_reg();
                // Gettings the src operant
                #?((K))
                    let src = &mut Value::constantu32(insn.imm as u32);
                    let dst = vm.reg(dst_r);
                ##
                #?((X))
                    let (dst, src) = break_if_none!(vm.two_regs(dst_r, insn.src_reg()));
                ##
                #?((ALU32))
                    let width = 32;
                ##
                #?((ALU64))
                    let width = 64;
                ##

                #?((ALU32))
                    dst.lower_half_assign();
                ##

                dst.#=2(src, width);
                #?((ALU32))
                    dst.lower_half_assign();
                ##
                vm.update_reg(dst_r);
            }
            // ALU / ALU64: Unary operators
            [[BPF_ALU: ALU32, BPF_ALU64: ALU64], [BPF_K: K],
             [
                BPF_NEG: neg_assign,
             ]
            ] => {
                let dst_r = insn.dst_reg();
                let dst = vm.reg(dst_r);
                #?((ALU32))
                    dst.lower_half_assign();
                ##
                dst.#=2();
                vm.update_reg(dst_r);
            }
            // ALU / ALU64: Byte swap
            [[BPF_ALU: ALU32], [BPF_END: END],
             [
                BPF_TO_LE: host_to_le,
                BPF_TO_BE: host_to_be,
             ]
            ] => {
                let dst_r = insn.dst_reg();
                let dst = vm.reg(dst_r);
                dst.#=2(insn.imm);
                vm.update_reg(dst_r);
            }
            // JMP32 / JMP: Conditional
            [[BPF_JMP32: JMP32, BPF_JMP: JMP64], [BPF_X: X, BPF_K: K],
             [
                // Unsigned
                BPF_JEQ: jeq,
                BPF_JLT: jlt,
                BPF_JLE: jle,
                BPF_JSLT: jslt,
                BPF_JSLE: jsle,
                // Inverse
                BPF_JNE: jeq,
                BPF_JGT: jle,
                BPF_JGE: jlt,
                BPF_JSGT: jsle,
                BPF_JSGE: jslt,
                // Misc
                BPF_JSET: jset,
             ]
            ] => {
                #?((JMP32))
                    let width = 32;
                ##
                #?((JMP64))
                    let width = 64;
                ##

                let vm_bak = unsafe { (vm.dup() as *mut M).as_mut().unwrap() };
                let (dst_r, src_r) = (insn.dst_reg(), insn.src_reg());
                #?((K))
                    let _ = src_r;
                    let src_r = -1i8;
                    #?((BPF_JSGT)|(BPF_JSGE)|(BPF_JSLT)|(BPF_JSLE))
                        let src = &mut Value::constanti32(insn.imm);
                    ##
                    #?((__BPF_JSGT__,__BPF_JSGE__,__BPF_JSLT__,__BPF_JSLE__))
                        let src = &mut Value::constantu32(insn.imm as u32);
                    ##
                    let dst = vm.reg(dst_r);
                ##
                #?((X))
                    let (dst, src) = break_if_none!(vm.two_regs(dst_r, src_r));
                    let src_r = src_r as i8;
                ##
                let fork = Fork { target: pc.wrapping_add_signed(insn.off as isize), fall_through: pc };
                #?((BPF_JNE)|(BPF_JGT)|(BPF_JGE)|(BPF_JSGT)|(BPF_JSGE))
                    let fork = Fork { target: fork.fall_through, fall_through: fork.target };
                ##
                let result = vm_bak.#=2(
                    (dst_r as i8, dst),
                    (src_r, src),
                    fork,
                    width
                );
                pc = *vm_bak.pc();
                if let Some(branch) = result {
                    context.add_pending_branch(branch);
                }
            }
            // BPF_JA: Unconditional jump
            [[BPF_JMP: JMP], [BPF_JA: JA]] => {
                pc = pc.wrapping_add_signed(insn.off as isize);
            }
            // BPF_EXIT: Exits
            [[BPF_JMP: JMP], [BPF_EXIT: EXIT]] => {
                if vm.return_relative() {
                    pc = *vm.pc();
                } else {
                    return;
                }
            }
            [[BPF_JMP: JMP], [BPF_CALL: CALL]] => {
                *vm.pc() = pc;
                run_call(insn, vm);
            }
            // Store / load
            [[BPF_LDX: LDX, BPF_STX: STX, BPF_ST: ST], [BPF_MEM: MEM],
             [
                BPF_B: "1",
                BPF_H: "2",
                BPF_W: "4",
                BPF_DW: "8",
             ]
            ] => {
                const SIZE: usize = #=2;
                #?((LDX))
                    let src = vm.ro_reg(insn.src_reg());
                    if let Some(value) = unsafe { src.get_at(insn.off, SIZE) } {
                        *vm.reg(insn.dst_reg()) = value;
                    } else {
                        vm.invalidate("Illegal access");
                    }
                    vm.update_reg(insn.src_reg());
                    vm.update_reg(insn.dst_reg());
                ##
                #?((STX))
                    let dst = vm.ro_reg(insn.dst_reg());
                    let src = vm.ro_reg(insn.src_reg());
                    unsafe {
                        if !dst.set_at(insn.off, SIZE, src) {
                            vm.invalidate("Illegal access");
                        }
                    }
                    vm.update_reg(insn.src_reg());
                    vm.update_reg(insn.dst_reg());
                ##
                #?((ST))
                    let dst = vm.ro_reg(insn.dst_reg());
                    unsafe {
                        if !dst.set_at(insn.off, SIZE, &Value::constant64(insn.imm as u32 as u64)) {
                            vm.invalidate("Illegal access");
                        }
                    }
                    vm.update_reg(insn.dst_reg());
                ##
            }
            [[BPF_LD: LD], [BPF_IMM: IMM], [BPF_DW: DW]] => {
                // TODO: Support relocation
                let value = insn.imm as u32 as u64 | (code[pc] & 0xFFFF_FFFF_0000_0000);
                *vm.reg(insn.dst_reg()) = Value::constant64(value);
                vm.update_reg(insn.dst_reg());
                pc += 1;
            }
            #[cfg(feature = "atomic32")]
            [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_W: W]] => {
                run_atomic(insn, vm, 4);
            }
            #[cfg(feature = "atomic64")]
            [[BPF_STX: STX], [BPF_ATOMIC: ATOMIC], [BPF_DW: DW]] => {
                run_atomic(insn, vm, 8);
            }
            _ => {
                vm.invalidate("Unrecognized opcode");
                break;
            }
        };
        *vm.pc() = pc;
    }
}

fn run_call<Value: VmValue, M: Vm<Value>>(insn: Instruction, vm: &mut RefMut<M>) {
    match insn.src_reg() {
        BPF_CALL_HELPER => vm.call_helper(insn.imm),
        BPF_CALL_PSEUDO => vm.call_relative(insn.off),
        BPF_CALL_KFUNC => vm.invalidate("Unsupported BPF_CALL"),
        _ => vm.invalidate("Invalid BPF_CALL"),
    }
}

fn run_atomic<Value: VmValue, M: Vm<Value>>(insn: Instruction, vm: &mut RefMut<M>, size: usize) {
    let atomic_code = insn.imm;
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
            let src_r = insn.src_reg();
            let (dst, src) = return_if_none!(vm.two_regs(insn.dst_reg(), src_r));
            let result = dst.#=1(insn.off, src, size);
            if result.is_err() {
                vm.invalidate("Atomic failed");
                return;
            }
            #?((FETCH))
                if let Ok(old) = result {
                    *vm.reg(src_r) = old;
                }
            ##
            vm.update_reg(insn.dst_reg());
            vm.update_reg(src_r);
        }
        [[BPF_ATOMIC_FETCH: FETCH], [BPF_ATOMIC_XCHG: XCHG]] => {
            let src_r =  insn.src_reg();
            let (src, dst) = return_if_none!(vm.two_regs(src_r, insn.dst_reg()));
            if let Ok(old) = dst.swap(insn.off, src, size) {
                *vm.reg(src_r) = old;
            } else {
                vm.invalidate("Atomic failed");
            }
            vm.update_reg(insn.dst_reg());
            vm.update_reg(src_r);
        }
        [[BPF_ATOMIC_FETCH: FETCH], [BPF_ATOMIC_CMPXCHG: CMPXCHG]] => {
            let src_r = insn.src_reg();
            let (dst, src, expected) = return_if_none!(vm.three_regs(insn.dst_reg(), src_r, 0));
            if let Ok(old) = dst.compare_exchange(insn.off, expected, src, size) {
                *vm.reg(0) = old;
            } else {
                vm.invalidate("Atomic failed");
            }
            vm.update_reg(insn.dst_reg());
            vm.update_reg(0);
            vm.update_reg(src_r);
        }
        _ => vm.invalidate("Atomic failed"),
    };
}
