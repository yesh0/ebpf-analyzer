//! This file contains the [Vm] trait used by the interpreter
//! as well as a VM implemtation [UncheckedVm] working as an interpreter.

use core::{cell::UnsafeCell, num::Wrapping, mem::swap};

use alloc::vec::Vec;
use ebpf_consts::{READABLE_REGISTER_COUNT, STACK_REGISTER, STACK_SIZE, WRITABLE_REGISTER_COUNT};

use crate::{safe::{mut_borrow_items, safe_ref_unsafe_cell}, spec::Instruction};

use super::{
    context::Forker,
    helper::HelperCollection,
    value::{Verifiable, VmValue},
};

/// VM interface for eBPF
pub trait Vm<Value: VmValue>: Forker<Value, Self> {
    /// Tells if the VM is valid
    ///
    /// The state should become invalid if anything listed below is detected:
    /// 1. Getting / setting values for non-existent registers;
    /// 2. Setting values for read-only registers;
    /// 3. Getting / setting values for non-existent stack members;
    /// 4. Setting invalid values;
    /// 5. Setting an invalid PC (well usually this has been checked by the block analyzer);
    /// 6. Calling the `invalidate` function.
    fn is_valid(&self) -> bool;
    /// Invalidates the VM, most often triggered by illegal intruction
    fn invalidate(&self, message: &'static str);
    /// Gets / Sets the Program Counter (PC)
    fn pc(&mut self) -> &mut usize;
    /// Gets the value of a register
    fn reg(&mut self, i: u8) -> &mut Value;
    /// Gets the value of a register
    fn ro_reg(&self, i: u8) -> &Value;
    /// Duplicates the reference
    ///
    /// # Safety
    /// It just returns the mut reference.
    /// Use it to get an reference behind a [RefMut] if you absolutely need it.
    unsafe fn dup(&mut self) -> &mut Self;
    /// Gets the values of two registers
    ///
    /// The implementation should support double borrows,
    /// by possibly allocating an extra temporary value.
    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut Value, &mut Value)>;
    /// Gets the values of two registers
    fn three_regs(&mut self, i: u8, j: u8, k: u8) -> Option<(&mut Value, &mut Value, &mut Value)>;
    /// Checks if a certain register is invalidated
    fn update_reg(&mut self, reg: u8);
    /// Calls a helper function
    fn call_helper(&mut self, helper: i32);
    /// Calls a inner function
    fn call_relative(&mut self, imm: i32);
    /// Returns from a function
    ///
    /// It returns `false` if the stack frame is empty and the interpreter should now stop.
    fn return_relative(&mut self) -> bool;
    /// Loads an immediate value by relocation
    fn load_imm64(&mut self, insn: &Instruction, next: u64) -> Option<Value>;
}

/// Saves the caller pc, callee saved registers and its stack
#[derive(Clone)]
pub struct CallerContext<Value: VmValue, Stack> {
    /// The caller pc (pointing the instruction after the call)
    pub pc: usize,
    /// Callee saved registers (`r6, r7, r8, r9`)
    pub registers: [Value; 4],
    /// Stack
    pub stack: Stack,
}

struct UncheckedInnerVm<Value: VmValue> {
    invalid: Option<&'static str>,
    pc: usize,
    call_trace: Vec<CallerContext<Value, Vec<Value>>>,
    registers: [Value; READABLE_REGISTER_COUNT as usize],
    stack: Vec<Value>,
    helpers: HelperCollection,
    /// Temporary value
    ///
    /// Rust forbids borrowing the same value twice,
    /// thus making safe implementation of instructions like `mul r1, r1` impossible.
    ///
    /// Currently we just use an extra temporary value for double borrows
    /// and forbid triple borrows (for BPF_ATOMIC_CMPXCHG using `r0`).
    temp: Value,
}

/// A VM impl
pub struct UncheckedVm<Value: VmValue>(UnsafeCell<UncheckedInnerVm<Value>>);

type Value = Wrapping<u64>;

impl Vm<Wrapping<u64>> for UncheckedVm<Wrapping<u64>> {
    fn is_valid(&self) -> bool {
        self.inner().invalid.is_none()
    }

    fn invalidate(&self, message: &'static str) {
        unsafe { (*self.0.get()).invalid = Some(message) }
    }

    fn pc(&mut self) -> &mut usize {
        &mut self.0.get_mut().pc
    }

    fn reg(&mut self, i: u8) -> &mut Value {
        if i < WRITABLE_REGISTER_COUNT {
            &mut self.0.get_mut().registers[i as usize]
        } else {
            self.invalidate("Register not allowed");
            &mut self.0.get_mut().registers[0]
        }
    }

    fn update_reg(&mut self, reg: u8) {
        if !self.ro_reg(reg).is_valid() {
            self.invalidate("Value invalid");
        }
    }

    fn ro_reg(&self, i: u8) -> &Value {
        if i < READABLE_REGISTER_COUNT {
            &self.inner().registers[i as usize]
        } else {
            self.invalidate("Register not allowed");
            &self.inner().registers[0]
        }
    }

    unsafe fn dup(&mut self) -> &mut Self {
        (self as *mut Self).as_mut().unwrap()
    }

    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut Value, &mut Value)> {
        if i == j {
            let inner = self.0.get_mut();
            if i < WRITABLE_REGISTER_COUNT {
                inner.temp = inner.registers[i as usize];
                Some((&mut inner.registers[i as usize], &mut inner.temp))
            } else {
                None
            }
        } else {
            mut_borrow_items!(self.0.get_mut().registers, [i as usize, j as usize], Value)
        }
    }

    fn three_regs(&mut self, i: u8, j: u8, k: u8) -> Option<(&mut Value, &mut Value, &mut Value)> {
        mut_borrow_items!(
            self.0.get_mut().registers,
            [i as usize, j as usize, k as usize],
            Value
        )
    }

    fn call_helper(&mut self, helper: i32) {
        if let Some(v) = self.inner().helpers.call_helper(
            helper,
            self.ro_reg(1).0,
            self.ro_reg(2).0,
            self.ro_reg(3).0,
            self.ro_reg(4).0,
            self.ro_reg(5).0,
        ) {
            self.reg(0).0 = v;
        } else {
            self.invalidate("Helper not found");
        }
    }

    fn call_relative(&mut self, imm: i32) {
        let inner = self.0.get_mut();
        let mut new_stack: Vec<Value> = Vec::new();
        new_stack.resize(STACK_SIZE / 8, Value::default());
        swap(&mut new_stack, &mut inner.stack);
        inner.call_trace.push(CallerContext { pc: inner.pc, registers: [
            inner.registers[6],
            inner.registers[7],
            inner.registers[8],
            inner.registers[9],
        ], stack: new_stack });
        inner.registers[10].0 = inner.stack.as_ptr() as u64 + STACK_SIZE as u64;

        inner.pc = inner.pc.wrapping_add_signed(imm as isize);
    }

    fn return_relative(&mut self) -> bool {
        let mut inner = self.0.get_mut();
        if let Some(caller) = inner.call_trace.pop() {
            inner.pc = caller.pc;
            for i in 6..=9 {
                inner.registers[i] = caller.registers[i - 6];
            }
            inner.stack = caller.stack;
            inner.registers[10].0 = inner.stack.as_ptr() as u64 + STACK_SIZE as u64;
            true
        } else {
            false
        }
    }

    fn load_imm64(&mut self, _insn: &Instruction, _next: u64) -> Option<Wrapping<u64>> {
        None
    }
}

impl<Value: VmValue> UncheckedVm<Value> {
    /// Creates a zero-initialized VM
    pub fn new(helpers: HelperCollection) -> Self {
        let mut vm = UncheckedInnerVm {
            invalid: None,
            pc: 0,
            call_trace: Vec::new(),
            registers: Default::default(),
            stack: Vec::new(),
            helpers,
            temp: Value::default(),
        };
        vm.stack.resize(STACK_SIZE / 8, Value::default());
        vm.registers[STACK_REGISTER as usize] =
            Value::constant64(vm.stack.as_ptr() as u64 + STACK_SIZE as u64);
        UncheckedVm(UnsafeCell::new(vm))
    }

    fn inner(&self) -> &UncheckedInnerVm<Value> {
        safe_ref_unsafe_cell(&self.0)
    }
}
