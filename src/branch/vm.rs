use core::{cell::RefCell, fmt::Debug};

use alloc::{rc::Rc, vec::Vec};
use ebpf_consts::{READABLE_REGISTER_COUNT, WRITABLE_REGISTER_COUNT};

use crate::{
    safe::mut_borrow_items,
    track::{
        pointees::{stack_region::StackRegion, Pointee},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
        TrackedValue,
    },
    vm::{
        value::Verifiable,
        vm::Vm,
    },
};

use super::{checked_value::CheckedValue, unsafe_invalidate};

/// The state of the verifying machine at a certain point
pub struct BranchState {
    pc: usize,
    invalid: Option<&'static str>,
    registers: [CheckedValue; 11],
    stack: Pointee,
    regions: Vec<Pointee>,
}

pub type Branch = Rc<RefCell<BranchState>>;

impl BranchState {
    /// Creates a new machine state
    ///
    /// Usually one should only use this at the start of verification.
    /// When branching, use [Clone] to duplicate the state.
    pub fn new(regions: Vec<Pointee>) -> Self {
        let mut state = Self {
            pc: 0,
            invalid: None,
            registers: Default::default(),
            stack: Rc::new(RefCell::new(StackRegion::new())),
            regions,
        };
        let mut frame = Pointer::new(
            PointerAttributes::NON_NULL
                | PointerAttributes::ARITHMETIC
                | PointerAttributes::READABLE
                | PointerAttributes::MUTABLE,
            state.stack.clone(),
        );
        frame += &Scalar::constant64(512);
        state.registers[10].0.replace(TrackedValue::Pointer(frame));
        state.stack.borrow_mut().set_id(0);
        for (id, region) in state.regions.iter().enumerate() {
            region.borrow_mut().set_id(id + 1);
        }
        state
    }

    pub fn get_region(&self, id: usize) -> Pointee {
        if id == 0 {
            self.stack.clone()
        } else {
            self.regions[id - 1].clone()
        }
    }
}

impl Clone for BranchState {
    /// Clones the state
    ///
    /// The underlying memory regions are duplicated,
    /// making the pointer in the generated state independent of the cloned one.
    fn clone(&self) -> Self {
        let mut regions = Vec::new();
        regions.reserve(self.regions.len());
        for region in &self.regions {
            regions.push(region.borrow().safe_clone());
        }
        let mut another = Self {
            pc: self.pc,
            invalid: None,
            registers: Default::default(),
            stack: self.stack.borrow().safe_clone(),
            regions,
        };
        let redirector = |i| another.get_region(i);
        another.stack.borrow_mut().redirects(&redirector);
        for region in &another.regions {
            region.borrow_mut().redirects(&redirector);
        }
        for (i, register) in self.registers.iter().enumerate() {
            let mut v = register.clone();
            if let Some(TrackedValue::Pointer(ref mut p)) = &mut v.0 {
                p.redirect(another.get_region(p.get_pointing_to()));
            }
            another.registers[i] = v;
        }
        another
    }
}

impl Vm<CheckedValue> for BranchState {
    fn pc(&mut self) -> &mut usize {
        &mut self.pc
    }

    fn invalidate(&self, message: &'static str) {
        unsafe {
            unsafe_invalidate!(&self.invalid, Option<&'static str>, Some(message));
        }
    }

    fn is_valid(&self) -> bool {
        self.invalid.is_none()
    }

    fn reg(&mut self, i: u8) -> &mut CheckedValue {
        if i < WRITABLE_REGISTER_COUNT {
            &mut self.registers[i as usize]
        } else {
            self.invalidate("Register invalid");
            &mut self.registers[0]
        }
    }

    fn update_reg(&mut self, reg: u8) {
        if !self.ro_reg(reg).is_valid() {
            self.invalidate("Register invalid")
        }
    }

    fn ro_reg(&self, i: u8) -> &CheckedValue {
        if i < READABLE_REGISTER_COUNT {
            &self.registers[i as usize]
        } else {
            self.invalidate("Register invalid");
            &self.registers[0]
        }
    }

    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut CheckedValue, &mut CheckedValue)> {
        mut_borrow_items!(self.registers, [i as usize, j as usize], CheckedValue)
    }

    fn three_regs(
        &mut self,
        i: u8,
        j: u8,
        k: u8,
    ) -> Option<(&mut CheckedValue, &mut CheckedValue, &mut CheckedValue)> {
        mut_borrow_items!(
            self.registers,
            [i as usize, j as usize, k as usize],
            CheckedValue
        )
    }

    unsafe fn dup(&mut self) -> &mut Self {
        (self as *mut Self).as_mut().unwrap()
    }
}

impl Debug for BranchState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("BranchState {{\n"))?;
        f.write_fmt(format_args!("  pc:    {}\n", self.pc))?;
        f.write_fmt(format_args!("  regs:  {:?}\n", self.registers))?;
        f.write_fmt(format_args!("  stack: {:?}\n", self.stack))?;
        f.write_fmt(format_args!("}} // End BranchState\n"))
    }
}

#[cfg(test)]
fn test_clone_or_not(clone: bool) {
    use crate::vm::value::Dereference;
    let mut vm = BranchState::new(Vec::new());
    let offset = &Scalar::constant64(512 - 4);
    assert!(vm
        .stack
        .borrow_mut()
        .set(&offset, 4, &TrackedValue::Scalar(Scalar::constant64(1)))
        .is_ok());
    for i in 2..10 {
        match unsafe { vm.ro_reg(10).get_at(-4, 32) } {
            Some(CheckedValue(Some(TrackedValue::Scalar(s)))) => {
                assert!(s.value64().unwrap() == i - 1)
            }
            _ => panic!(),
        }
        assert!(vm
            .stack
            .borrow_mut()
            .set(&offset, 4, &TrackedValue::Scalar(Scalar::constant64(i)))
            .is_ok());
        match unsafe { vm.ro_reg(10).get_at(-4, 32) } {
            Some(CheckedValue(Some(TrackedValue::Scalar(s)))) => {
                assert!(s.value64().unwrap() == i, "{}, {}", s.value64().unwrap(), i)
            }
            _ => panic!(),
        }
        if clone {
            vm = vm.clone();
        }
    }
}

#[test]
pub fn test_no_clone() {
    test_clone_or_not(false);
}

#[test]
pub fn test_cloned() {
    test_clone_or_not(true);
}
