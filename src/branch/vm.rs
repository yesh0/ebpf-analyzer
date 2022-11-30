//! This modules contains an implementation of [Vm] dedicated to eBPF verification: [BranchState].
//!
//! Since the VM branches when doing conditional jumps (see [super::fork]),
//! usually the VM is kept behind an [Rc] with [Branch].

use core::{
    cell::{RefCell, UnsafeCell},
    fmt::Debug,
};

use alloc::{rc::Rc, vec::Vec};
use ebpf_consts::{READABLE_REGISTER_COUNT, WRITABLE_REGISTER_COUNT};

use crate::{
    interpreter::{value::Verifiable, vm::Vm},
    safe::{mut_borrow_items, safe_ref_unsafe_cell},
    spec::proto::VerifiableCall,
    track::{
        pointees::{stack_region::StackRegion, Pointee},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
        TrackedValue,
    },
};

use super::{
    checked_value::CheckedValue,
    id::{Id, IdGen},
    resource::ResourceTracker,
};

/// A collection of used helper functions
///
/// This assumes that the user uses a set of helpers determined at compile time.
pub type StaticHelpers = &'static [&'static dyn VerifiableCall<CheckedValue, BranchState>];

/// Inner state of [BranchState]
struct InnerState {
    pc: usize,
    ids: IdGen,
    invalid: Option<&'static str>,
    registers: [CheckedValue; 11],
    stack: Pointee,
    regions: Vec<Pointee>,
    helpers: StaticHelpers,
    resources: ResourceTracker,
}

/// The state of the verifying machine at a certain point
///
/// It contains, for now, the following information:
/// - the program counter
/// - validity of the current execution path
/// - managed memory regions (including a stack)
/// - registers
pub struct BranchState(UnsafeCell<InnerState>);

/// [BranchState] wrapped in a [RefCell] in an [Rc]
pub type Branch = Rc<RefCell<BranchState>>;

impl BranchState {
    /// Creates a new machine state
    ///
    /// Usually one should only use this at the start of verification.
    /// When branching, use [Clone] to duplicate the state.
    pub fn new(regions: Vec<Pointee>, helpers: StaticHelpers) -> Self {
        let mut state = InnerState {
            pc: 0,
            ids: IdGen::default(),
            invalid: None,
            registers: Default::default(),
            stack: Rc::new(RefCell::new(StackRegion::new())),
            resources: ResourceTracker::default(),
            regions,
            helpers,
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
        state.stack.borrow_mut().set_id(state.ids.next_id());
        for region in &state.regions {
            region.borrow_mut().set_id(state.ids.next_id());
        }
        Self(UnsafeCell::new(state))
    }

    fn get_region(&self, id: Id) -> Pointee {
        if id == self.inner().stack.borrow_mut().get_id() {
            self.inner().stack.clone()
        } else {
            let index = self
                .inner()
                .regions
                .binary_search_by(|r| r.borrow_mut().get_id().cmp(&id));
            self.inner().regions[index.ok().unwrap()].clone()
        }
    }

    fn get_region_except(&self, id: Id, borrowed: Id) -> Pointee {
        if id == self.inner().stack.borrow_mut().get_id() {
            self.inner().stack.clone()
        } else {
            let index = self.inner().regions.binary_search_by(|r| {
                r.try_borrow()
                    .map(|r| r.get_id())
                    .unwrap_or(borrowed)
                    .cmp(&id)
            });
            self.inner().regions[index.ok().unwrap()].clone()
        }
    }

    /// Adds the region and sets its id
    pub fn add_region(&mut self, region: Pointee) {
        region.borrow_mut().set_id(self.inner_mut().ids.next_id());
        self.inner_mut().regions.push(region);
    }

    fn inner(&self) -> &InnerState {
        safe_ref_unsafe_cell(&self.0)
    }

    fn inner_mut(&mut self) -> &mut InnerState {
        self.0.get_mut()
    }

    /// Retrieves the resource tracker
    pub fn resources(&mut self) -> &mut ResourceTracker {
        &mut self.inner_mut().resources
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
            ids: IdGen::default(),
            invalid: None,
            registers: Default::default(),
            stack: self.inner().stack.borrow().safe_clone(),
            resources: self.inner().resources.clone(),
            regions,
            helpers: self.inner().helpers,
        }));
        another
            .inner()
            .stack
            .borrow_mut()
            .redirects(&|i| another.get_region(i));
        for region in &another.inner().regions {
            let mut borrow = region.borrow_mut();
            let id = borrow.get_id();
            let redirector = |i| {
                if i == id {
                    region.clone()
                } else {
                    another.get_region_except(i, id)
                }
            };
            borrow.redirects(&redirector);
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

    fn call_helper(&mut self, helper: i32) {
        if helper <= 0 {
            self.invalidate("Invalid helper id");
        } else if let Some(helper) = self.inner().helpers.get(helper as usize) {
            if let Ok(v) = helper.call(self) {
                *self.reg(0) = v;
            } else {
                self.invalidate("Function call failed");
            }
        }
    }

    fn call_relative(&mut self, _offset: i16) {
        todo!()
    }

    fn return_relative(&mut self) -> bool {
        if !self.inner().resources.is_empty() {
            self.invalidate("Resource not cleaned up");
        }
        false
    }
}

impl Debug for BranchState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("BranchState {{\n"))?;
        if let Some(message) = self.inner().invalid {
            f.write_fmt(format_args!("  msg:   {}\n", message))?;
        }
        f.write_fmt(format_args!("  pc:    {}\n", self.inner().pc))?;
        f.write_fmt(format_args!("  regs:  {:?}\n", self.inner().registers))?;
        f.write_fmt(format_args!("  stack: {:?}\n", self.inner().stack))?;
        f.write_fmt(format_args!("}} // End BranchState\n"))
    }
}

#[cfg(test)]
fn test_clone_or_not(clone: bool) {
    use crate::interpreter::value::Dereference;
    let mut vm = BranchState::new(Vec::new(), &[]);
    let offset = &Scalar::constant64(512 - 4);
    assert!(vm
        .inner()
        .stack
        .borrow_mut()
        .set(offset, 4, &TrackedValue::Scalar(Scalar::constant64(1)))
        .is_ok());
    for i in 2..10 {
        match unsafe { vm.ro_reg(10).get_at(-4, 4) } {
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
        match unsafe { vm.ro_reg(10).get_at(-4, 4) } {
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
