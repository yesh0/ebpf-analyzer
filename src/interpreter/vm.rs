//! This file contains the [Vm] trait used by the interpreter
//! as well as a VM implemtation [UncheckedVm] working as an interpreter.

use core::{cell::UnsafeCell, num::Wrapping};

use alloc::vec::Vec;
use ebpf_consts::{READABLE_REGISTER_COUNT, STACK_REGISTER, STACK_SIZE, WRITABLE_REGISTER_COUNT};

use crate::safe::{mut_borrow_items, safe_ref_unsafe_cell};

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
    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut Value, &mut Value)>;
    /// Gets the values of two registers
    fn three_regs(&mut self, i: u8, j: u8, k: u8) -> Option<(&mut Value, &mut Value, &mut Value)>;
    /// Checks if a certain register is invalidated
    fn update_reg(&mut self, reg: u8);
    /// Call a helper function
    fn call_helper(&mut self, helper: i32);
}

struct UncheckedInnerVm<Value: VmValue> {
    invalid: Option<&'static str>,
    pc: usize,
    registers: [Value; READABLE_REGISTER_COUNT as usize],
    stack: Vec<Value>,
    helpers: HelperCollection,
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
        if !self.reg(reg).is_valid() {
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
        mut_borrow_items!(self.0.get_mut().registers, [i as usize, j as usize], Value)
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
}

impl<Value: VmValue> UncheckedVm<Value> {
    /// Creates a zero-initialized VM
    pub fn new(helpers: HelperCollection) -> Self {
        let mut vm = UncheckedInnerVm {
            invalid: None,
            pc: 0,
            registers: Default::default(),
            stack: Vec::new(),
            helpers,
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
