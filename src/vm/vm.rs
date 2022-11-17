use core::num::Wrapping;

use alloc::vec::Vec;
use ebpf_consts::{READABLE_REGISTER_COUNT, STACK_REGISTER, STACK_SIZE, WRITABLE_REGISTER_COUNT};

use crate::safe::mut_borrow_items;

use super::{
    context::Forker,
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
    unsafe fn dup(&mut self) -> &mut Self;
    /// Gets the values of two registers
    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut Value, &mut Value)>;
    /// Gets the values of two registers
    fn three_regs(&mut self, i: u8, j: u8, k: u8) -> Option<(&mut Value, &mut Value, &mut Value)>;
    /// Checks if a certain register is invalidated
    fn update_reg(&mut self, reg: u8);
}

/// A VM impl
pub struct UncheckedVm<Value: VmValue> {
    invalid: Option<&'static str>,
    pc: usize,
    registers: [Value; READABLE_REGISTER_COUNT as usize],
    stack: Vec<Value>,
}

type Value = Wrapping<u64>;

impl Vm<Wrapping<u64>> for UncheckedVm<Wrapping<u64>> {
    fn is_valid(&self) -> bool {
        self.invalid.is_none()
    }

    fn invalidate(&self, message: &'static str) {
        // Fully aware what I am doing
        unsafe {
            (*(self as *const Self as *mut Self))
                .invalid
                .replace(message);
        }
    }

    fn pc(&mut self) -> &mut usize {
        &mut self.pc
    }

    fn reg(&mut self, i: u8) -> &mut Value {
        if i < WRITABLE_REGISTER_COUNT {
            &mut self.registers[i as usize]
        } else {
            self.invalidate("Register not allowed");
            &mut self.registers[0]
        }
    }

    fn update_reg(&mut self, reg: u8) {
        if !self.reg(reg).is_valid() {
            self.invalidate("Value invalid");
        }
    }

    fn ro_reg(&self, i: u8) -> &Value {
        if i < READABLE_REGISTER_COUNT {
            &self.registers[i as usize]
        } else {
            self.invalidate("Register not allowed");
            &self.registers[0]
        }
    }

    unsafe fn dup(&mut self) -> &mut Self {
        (self as *mut Self).as_mut().unwrap()
    }

    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut Value, &mut Value)> {
        mut_borrow_items!(self.registers, [i as usize, j as usize], Value)
    }

    fn three_regs(&mut self, i: u8, j: u8, k: u8) -> Option<(&mut Value, &mut Value, &mut Value)> {
        mut_borrow_items!(self.registers, [i as usize, j as usize, k as usize], Value)
    }
}

impl<Value: VmValue> UncheckedVm<Value> {
    /// Creates a zero-initialized VM
    pub fn new() -> Self {
        let mut vm = UncheckedVm {
            invalid: None,
            pc: 0,
            registers: Default::default(),
            stack: Vec::new(),
        };
        vm.stack.resize(STACK_SIZE / 8, Value::default());
        vm.registers[STACK_REGISTER as usize] =
            Value::constant64(vm.stack.as_ptr() as u64 + STACK_SIZE as u64);
        vm
    }
}
