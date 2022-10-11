use ebpf_consts::{READABLE_REGISTER_COUNT, STACK_SIZE, WRITABLE_REGISTER_COUNT};

use super::value::VmValue;

/// VM interface for eBPF
pub trait Vm<Value: VmValue> {
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
    fn invalidate(&mut self);
    /// Gets / Sets the Program Counter (PC)
    fn pc(&mut self) -> &mut usize;
    /// Gets the value of a register
    fn get_reg(&mut self, i: u8) -> &Value;
    /// Sets the value for a register
    fn set_reg(&mut self, i: u8, v: Value);
    /// Gets the value of a stack member
    fn get_stack(&mut self, i: usize) -> &Value;
    /// Sets the value for a stack member
    fn set_stack(&mut self, i: usize, v: Value);
}

/// A VM impl
pub struct UncheckedVm<Value: VmValue> {
    valid: bool,
    pc: usize,
    registers: [Value; READABLE_REGISTER_COUNT as usize],
    stack: [Value; STACK_SIZE],
}

impl<Value: VmValue> Vm<Value> for UncheckedVm<Value> {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn invalidate(&mut self) {
        self.valid = false
    }

    fn pc(&mut self) -> &mut usize {
        &mut self.pc
    }

    fn get_reg(&mut self, i: u8) -> &Value {
        if i < READABLE_REGISTER_COUNT {
            &self.registers[i as usize]
        } else {
            self.invalidate();
            &self.registers[0]
        }
    }

    fn set_reg(&mut self, i: u8, v: Value) {
        if v.is_valid() {
            if i < WRITABLE_REGISTER_COUNT {
                self.registers[i as usize] = v;
            } else {
                self.invalidate();
            }
        } else {
            self.invalidate();
        }
    }

    fn get_stack(&mut self, i: usize) -> &Value {
        if i < STACK_SIZE {
            &self.stack[i]
        } else {
            self.invalidate();
            &self.stack[0]
        }
    }

    fn set_stack(&mut self, i: usize, v: Value) {
        if v.is_valid() {
            if i < STACK_SIZE {
                self.stack[i] = v;
            } else {
                self.invalidate();
            }
        } else {
            self.invalidate();
        }
    }
}

impl<Value: VmValue> UncheckedVm<Value> {
    /// Creates a zero-initialized VM
    pub fn new() -> Self {
        UncheckedVm {
            valid: true,
            pc: 0,
            registers: [Value::default(); READABLE_REGISTER_COUNT as usize],
            stack: [Value::default(); STACK_SIZE],
        }
    }
}
