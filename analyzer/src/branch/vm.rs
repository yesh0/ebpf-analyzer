//! This modules contains an implementation of [Vm] dedicated to eBPF verification: [BranchState].
//!
//! Since the VM branches when doing conditional jumps (see [super::fork]),
//! usually the VM is kept behind an [Rc] with [Branch].

use core::{
    cell::{RefCell, UnsafeCell},
    fmt::Debug,
};

use alloc::{rc::Rc, vec::Vec, string::{String, ToString}};
use ebpf_consts::{READABLE_REGISTER_COUNT, WRITABLE_REGISTER_COUNT, BPF_IMM64_MAP_FD};

use crate::{
    interpreter::{
        value::Verifiable,
        vm::{CallerContext, Vm},
    },
    safe::{mut_borrow_items, safe_ref_unsafe_cell},
    spec::{proto::VerifiableCall, Instruction},
    track::{
        pointees::{empty_region::EmptyRegion, pointed, stack_region::StackRegion, Pointee, map_resource::SimpleMap},
        pointer::Pointer,
        scalar::Scalar,
        TrackedValue,
    }, analyzer::MapInfo,
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
    invalid: Vec<String>,
    registers: [CheckedValue; 11],
    /// A temporary value to allow borrowing the "same" register
    /// for instructions like `mul r1, r1`
    ///
    /// The value is only exposed when calling `two_regs` with two identical register index,
    /// and should always be valid.
    temp_reg: CheckedValue,
    call_trace: Vec<CallerContext<CheckedValue, Pointee>>,
    stack: Pointee,
    regions: Vec<Pointee>,
    helpers: StaticHelpers,
    resources: ResourceTracker,
    maps: Rc<RefCell<Vec<(i32, Pointee)>>>,
}

impl InnerState {
    pub(super) fn gen_stack_pointer(&self) -> Pointer {
        Pointer::nrwa(self.stack.clone())
    }
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
    pub fn new(helpers: StaticHelpers, maps: Vec<(i32, MapInfo)>) -> Self {
        let mut state = InnerState {
            pc: 0,
            ids: IdGen::default(),
            invalid: Vec::new(),
            registers: Default::default(),
            temp_reg: Scalar::unknown().into(),
            call_trace: Vec::new(),
            stack: pointed(StackRegion::new()),
            resources: ResourceTracker::default(),
            regions: alloc::vec![EmptyRegion::instance()],
            helpers,
            maps: Rc::new(RefCell::new(Vec::new())),
        };
        let mut frame = state.gen_stack_pointer();
        frame += &Scalar::constant64(512);
        *state.registers[10].inner_mut() = Some(TrackedValue::Pointer(frame));
        let id = state.resources.external(&mut state.ids);
        debug_assert!(id == 1);
        state.stack.borrow_mut().set_id(id);

        // Initialize map regions
        let map_fds = state.maps.clone();
        let mut state_maps = map_fds.borrow_mut();
        for (fd, info) in maps {
            let map = pointed(SimpleMap::new(info.key_size as usize, info.value_size as usize));
            state_maps.push((fd, map));
        }

        let mut vm = Self(UnsafeCell::new(state));
        for (_, region) in state_maps.iter() {
            vm.add_external_resource(region.clone());
        }
        vm
    }

    fn get_region(&self, id: Id) -> Pointee {
        if id == self.inner().stack.borrow_mut().get_id() {
            self.inner().stack.clone()
        } else {
            let index = self
                .inner()
                .regions
                .binary_search_by(|r| r.borrow_mut().get_id().cmp(&id));
            self.inner().regions[index.unwrap()].clone()
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
            self.inner().regions[index.unwrap()].clone()
        }
    }

    /// Starts tracking this resource,
    /// marking it as a supplied resource, without the need to release it manually.
    pub fn add_external_resource(&mut self, region: Pointee) {
        let inner = self.inner_mut();
        let id = inner.resources.external(&mut inner.ids);
        region.borrow_mut().set_id(id);
        inner.regions.push(region);
    }

    /// Marks an external resource as unavailable.
    pub fn remove_external_resource(&mut self, id: Id) {
        let inner = self.inner_mut();
        if inner.resources.invalidate_external(id) {
            // TODO: Invalidate
        } else {
            self.invalidate("External resource");
        }
    }

    /// Starts tracking this resource,
    /// marking it as a program-allocated resource, needed to get released.
    pub fn add_allocated_resource(&mut self, region: Pointee) {
        let inner = self.inner_mut();
        let id = inner.resources.allocate(&mut inner.ids);
        region.borrow_mut().set_id(id);
        inner.regions.push(region);
    }

    /// Marks an allocated resource as released.
    pub fn deallocate_resource(&mut self, id: Id) {
        let inner = self.inner_mut();
        if inner.resources.deallocate(id) {
            // Redirect all pointer to this region into an invalid region
            let invalid = inner.regions[0].clone();
            // Redirect registers
            for reg in &mut inner.registers {
                if let Some(TrackedValue::Pointer(p)) = reg.inner_mut() {
                    if p.is_pointing_to(id) {
                        p.redirect(invalid.clone());
                    }
                }
            }
            let redirector = |i| if i == id { Some(invalid.clone()) } else { None };
            // Redirect stack
            inner.stack.borrow_mut().redirects(&redirector);
            // Redirect regions
            for region in &inner.regions {
                region.borrow_mut().redirects(&redirector);
            }
            // TODO: Consider invalidating pointers from call_trace
            // TODO: Maybe remove that region from self.inner().regions
        } else {
            self.invalidate("Deallocating unknown resource");
        }
    }

    /// Returns `true` if the register is a pointer
    /// and it points to a non-existing resource
    pub fn is_invalid_resource(&self, i: u8) -> bool {
        if let Some(TrackedValue::Pointer(p)) = self.ro_reg(i).inner() {
            let id = p.get_pointing_to();
            !self.inner().resources.contains(id)
        } else {
            false
        }
    }

    /// Gets the error messages
    pub fn messages(&self) -> &[String] {
        &self.inner().invalid
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
        let inner = self.inner();
        regions.reserve(inner.regions.len());
        for region in &inner.regions {
            regions.push(region.borrow().safe_clone());
        }
        let mut another = Self(UnsafeCell::new(InnerState {
            pc: inner.pc,
            ids: IdGen::default(),
            invalid: Vec::new(),
            registers: Default::default(),
            temp_reg: inner.temp_reg.clone(),
            call_trace: inner.call_trace.clone(),
            stack: inner.stack.borrow().safe_clone(),
            resources: inner.resources.clone(),
            regions,
            helpers: inner.helpers,
            maps: inner.maps.clone(),
        }));
        another
            .inner()
            .stack
            .borrow_mut()
            .redirects(&|i| Some(another.get_region(i)));
        for region in &another.inner().regions {
            let mut borrow = region.borrow_mut();
            let id = borrow.get_id();
            let redirector = |i| {
                Some(if i == id {
                    region.clone()
                } else {
                    another.get_region_except(i, id)
                })
            };
            borrow.redirects(&redirector);
        }
        for (i, register) in inner.registers.iter().enumerate() {
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
            (*self.0.get()).invalid.push(message.to_string());
        }
    }

    fn is_valid(&self) -> bool {
        self.inner().invalid.is_empty() || !self.inner().temp_reg.is_valid()
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
        if !(self.ro_reg(reg).is_valid() && self.inner().temp_reg.is_valid()) {
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
        if i == j {
            if i < WRITABLE_REGISTER_COUNT {
                let inner = self.inner_mut();
                inner.temp_reg = inner.registers[i as usize].clone();
                Some((&mut inner.registers[i as usize], &mut inner.temp_reg))
            } else {
                None
            }
        } else {
            mut_borrow_items!(
                self.inner_mut().registers,
                [i as usize, j as usize],
                CheckedValue
            )
        }
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
                if !self.is_valid() {
                    // Keep r1~r5 for debugging
                    return;
                }
                for i in 1..=5 {
                    *self.reg(i) = CheckedValue::default();
                }
            } else {
                self.invalidate("Function call failed");
            }
        } else {
            self.invalidate("Invalid helper id");
        }
    }

    fn call_relative(&mut self, imm: i32) {
        let inner = self.inner_mut();
        inner.call_trace.push(CallerContext {
            pc: inner.pc,
            registers: [
                inner.registers[6].clone(),
                inner.registers[7].clone(),
                inner.registers[8].clone(),
                inner.registers[9].clone(),
            ],
            stack: inner.stack.clone(),
        });
        for i in 6..=9 {
            inner.registers[i] = CheckedValue::default();
        }
        inner.pc = inner.pc.wrapping_add_signed(imm as isize);
        let stack = pointed(StackRegion::new());
        inner.stack = stack.clone();
        inner.registers[10] = inner.gen_stack_pointer().into();
        self.add_external_resource(stack);
    }

    fn return_relative(&mut self) -> bool {
        let id = self.inner().stack.borrow_mut().get_id();
        self.remove_external_resource(id);
        let inner = self.inner_mut();
        if let Some(caller) = inner.call_trace.pop() {
            inner.pc = caller.pc;
            inner.stack = caller.stack.clone();
            inner.registers[10] = inner.gen_stack_pointer().into();
            for i in 6..=9 {
                inner.registers[i] = caller.registers[i - 6].clone();
            }
            true
        } else {
            if !self.inner().resources.is_empty() {
                self.invalidate("Resource not cleaned up");
            }
            false
        }
    }

    fn load_imm64(&mut self, insn: &Instruction, _next: u64) -> Option<CheckedValue> {
        match insn.src_reg() {
            BPF_IMM64_MAP_FD => {
                let fd = insn.imm;
                let maps = self.inner_mut().maps.borrow_mut();
                for (i, map) in maps.iter() {
                    if fd == *i {
                        return Some(Pointer::nrw(map.clone()).into());
                    }
                }
                None
            }
            _ => None,
        }
    }
}

impl Debug for BranchState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("BranchState {{\n"))?;
        if !self.inner().invalid.is_empty() {
            f.write_fmt(format_args!("  msg:   {:?}\n", self.inner().invalid))?;
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
    let mut vm = BranchState::new(&[], Vec::new());
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
