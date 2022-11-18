use core::{
    cell::{RefCell, UnsafeCell},
    fmt::Debug,
};

use alloc::{rc::Rc, vec::Vec};
use ebpf_consts::{READABLE_REGISTER_COUNT, WRITABLE_REGISTER_COUNT};

use crate::{
    interpreter::{value::Verifiable, vm::Vm},
    safe::{mut_borrow_items, safe_ref_unsafe_cell},
    track::{
        pointees::{stack_region::StackRegion, Pointee},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
        TrackedValue,
    },
};

use super::checked_value::CheckedValue;

struct InnerState {
    pc: usize,
    invalid: Option<&'static str>,
    registers: [CheckedValue; 11],
    stack: Pointee,
    regions: Vec<Pointee>,
}

/// The state of the verifying machine at a certain point
pub struct BranchState(UnsafeCell<InnerState>);

pub type Branch = Rc<RefCell<BranchState>>;

impl BranchState {
    /// Creates a new machine state
    ///
    /// Usually one should only use this at the start of verification.
    /// When branching, use [Clone] to duplicate the state.
    pub fn new(regions: Vec<Pointee>) -> Self {
        let mut state = InnerState {
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
        *state.registers[10].inner_mut() = Some(TrackedValue::Pointer(frame));
        state.stack.borrow_mut().set_id(0);
        for (id, region) in state.regions.iter().enumerate() {
            region.borrow_mut().set_id(id + 1);
        }
        Self(UnsafeCell::new(state))
    }

    pub fn get_region(&self, id: usize) -> Pointee {
        if id == 0 {
            self.inner().stack.clone()
        } else {
            self.inner().regions[id - 1].clone()
        }
    }

    fn inner(&self) -> &InnerState {
        safe_ref_unsafe_cell(&self.0)
    }

    fn inner_mut(&mut self) -> &mut InnerState {
        self.0.get_mut()
    }
}

impl Clone for BranchState {
    /// Clones the state
    ///
    /// The underlying memory regions are duplicated,
    /// making the pointer in the generated state independent of the cloned one.
    fn clone(&self) -> Self {
        let mut regions = Vec::new();
        regions.reserve(self.inner().regions.len());
        for region in &self.inner().regions {
            regions.push(region.borrow().safe_clone());
        }
        let mut another = Self(UnsafeCell::new(InnerState {
            pc: self.inner().pc,
            invalid: None,
            registers: Default::default(),
            stack: self.inner().stack.borrow().safe_clone(),
            regions,
        }));
        let redirector = |i| another.get_region(i);
        another.inner().stack.borrow_mut().redirects(&redirector);
        for region in &another.inner().regions {
            region.borrow_mut().redirects(&redirector);
        }
        for (i, register) in self.inner().registers.iter().enumerate() {
            let mut v = register.clone();
            if let Some(TrackedValue::Pointer(ref mut p)) = v.inner_mut() {
                p.redirect(another.get_region(p.get_pointing_to()));
            }
            another.inner_mut().registers[i] = v;
        }
        another
    }
}

impl Vm<CheckedValue> for BranchState {
    fn pc(&mut self) -> &mut usize {
        &mut self.inner_mut().pc
    }

    fn invalidate(&self, message: &'static str) {
        unsafe {
            // Safe since we are single-threaded and only invalidating things
            (*self.0.get()).invalid = Some(message)
        }
    }

    fn is_valid(&self) -> bool {
        self.inner().invalid.is_none()
    }

    fn reg(&mut self, i: u8) -> &mut CheckedValue {
        if i < WRITABLE_REGISTER_COUNT {
            &mut self.inner_mut().registers[i as usize]
        } else {
            self.invalidate("Register invalid");
            &mut self.inner_mut().registers[0]
        }
    }

    fn update_reg(&mut self, reg: u8) {
        if !self.ro_reg(reg).is_valid() {
            self.invalidate("Register invalid")
        }
    }

    fn ro_reg(&self, i: u8) -> &CheckedValue {
        if i < READABLE_REGISTER_COUNT {
            &self.inner().registers[i as usize]
        } else {
            self.invalidate("Register invalid");
            &self.inner().registers[0]
        }
    }

    fn two_regs(&mut self, i: u8, j: u8) -> Option<(&mut CheckedValue, &mut CheckedValue)> {
        mut_borrow_items!(
            self.inner_mut().registers,
            [i as usize, j as usize],
            CheckedValue
        )
    }

    fn three_regs(
        &mut self,
        i: u8,
        j: u8,
        k: u8,
    ) -> Option<(&mut CheckedValue, &mut CheckedValue, &mut CheckedValue)> {
        mut_borrow_items!(
            self.inner_mut().registers,
            [i as usize, j as usize, k as usize],
            CheckedValue
        )
    }

    unsafe fn dup(&mut self) -> &mut Self {
        (self as *mut Self).as_mut().unwrap()
    }

    fn call_helper(&mut self, _helper: i32) {
        todo!()
    }
}

impl Debug for BranchState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("BranchState {{\n"))?;
        f.write_fmt(format_args!("  pc:    {}\n", self.inner().pc))?;
        f.write_fmt(format_args!("  regs:  {:?}\n", self.inner().registers))?;
        f.write_fmt(format_args!("  stack: {:?}\n", self.inner().stack))?;
        f.write_fmt(format_args!("}} // End BranchState\n"))
    }
}

#[cfg(test)]
fn test_clone_or_not(clone: bool) {
    use crate::interpreter::value::Dereference;
    let mut vm = BranchState::new(Vec::new());
    let offset = &Scalar::constant64(512 - 4);
    assert!(vm
        .inner()
        .stack
        .borrow_mut()
        .set(offset, 4, &TrackedValue::Scalar(Scalar::constant64(1)))
        .is_ok());
    for i in 2..10 {
        match unsafe { vm.ro_reg(10).get_at(-4, 32) } {
            Some(v) => {
                if let Some(TrackedValue::Scalar(s)) = v.inner() {
                    assert!(s.value64().unwrap() == i - 1);
                }
            }
            _ => panic!(),
        }
        assert!(vm
            .inner()
            .stack
            .borrow_mut()
            .set(offset, 4, &TrackedValue::Scalar(Scalar::constant64(i)))
            .is_ok());
        match unsafe { vm.ro_reg(10).get_at(-4, 32) } {
            Some(v) => {
                if let Some(TrackedValue::Scalar(s)) = v.inner() {
                    assert!(s.value64().unwrap() == i, "{}, {}", s.value64().unwrap(), i);
                }
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
