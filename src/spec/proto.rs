//! Function prototype information

use core::ops::RangeInclusive;

use crate::{
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::{value::VmValue, vm::Vm},
    track::{scalar::Scalar, TrackError},
};

/// Error codes for illegal functions
#[derive(Debug)]
pub enum IllegalFunctionCall {
    /// Using a register never assigned to before
    UsedRegisterNotInitialized,
    /// Type mismatch (pointer, scalar, ...)
    TypeMismatch,
    /// Expecting a constant value
    NotAConstant,
    /// A pointer or a constant is out of range
    OutofRange,
    /// Pointer access error
    IllegalPointer(TrackError),
}

/// Function prototype information
pub trait VerifiableCall<Value: VmValue, M: Vm<Value>> {
    /// Verifies the function call
    fn call(&self, vm: &mut M) -> Result<Value, IllegalFunctionCall>;
}

/// Hard-coded allowed argument types
#[derive(Default)]
pub enum ArgumentType {
    /// Any value, including uninit values
    #[default]
    Any,
    /// Some value, excluding uninit values
    Some,
    /// Constant scalar value
    Constant(RangeInclusive<u64>),
    /// Any scalar value
    Scalar,
    /// Pointer to a memory region of fixed size
    FixedMemory(usize),
    /// Ranged memory, with its size specified by another register
    DynamicMemory(u8),
}

/// Specifies the arguments
pub type Arguments = [ArgumentType; 5];

/// Verifies the call basing on static information
pub struct StaticFunctionCall {
    arguments: Arguments,
}

impl StaticFunctionCall {
    /// Creates a function prototype
    pub const fn new(arguments: Arguments) -> StaticFunctionCall {
        StaticFunctionCall { arguments }
    }
}

impl VerifiableCall<CheckedValue, BranchState> for StaticFunctionCall {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        for i in 0..5u8 {
            let arg = &self.arguments[i as usize];
            if let ArgumentType::DynamicMemory(reg) = arg {
                let (a, b) = vm.two_regs(i, *reg).unwrap();
                a.check_arg_type(&self.arguments[i as usize], Some(b))?;
            } else {
                vm.ro_reg(i)
                    .check_arg_type(&self.arguments[i as usize], None)?;
            }
        }
        Ok(Scalar::unknown().into())
    }
}

#[test]
fn test_arg_check() {
    let v: CheckedValue = Scalar::unknown().into();
    assert!(v.check_arg_type(&ArgumentType::Any, None).is_ok());
    assert!(v.check_arg_type(&ArgumentType::Scalar, None).is_ok());
    assert!(v
        .check_arg_type(&ArgumentType::Constant(0..=0), None)
        .is_err());

    let v: CheckedValue = Scalar::constant64(1).into();
    assert!(v
        .check_arg_type(&ArgumentType::Constant(0..=0), None)
        .is_err());
    assert!(v
        .check_arg_type(&ArgumentType::Constant(0..=1), None)
        .is_ok());
    assert!(v
        .check_arg_type(&ArgumentType::Constant(1..=1), None)
        .is_ok());
    assert!(v
        .check_arg_type(&ArgumentType::FixedMemory(8), None)
        .is_err());

    use crate::track::pointer::Pointer;
    use crate::track::pointer::PointerAttributes;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    let v: CheckedValue = Pointer::new(
        PointerAttributes::NON_NULL | PointerAttributes::MUTABLE,
        Rc::new(RefCell::new(
            crate::track::pointees::stack_region::StackRegion::default(),
        )),
    )
    .into();
    assert!(v.check_arg_type(&ArgumentType::Any, None).is_ok());
    assert!(v.check_arg_type(&ArgumentType::Scalar, None).is_err());
    assert!(v
        .check_arg_type(&ArgumentType::Constant(0..=100), None)
        .is_err());
    assert!(v
        .check_arg_type(&ArgumentType::FixedMemory(8), None)
        .is_ok());
    assert!(v
        .check_arg_type(
            &ArgumentType::DynamicMemory(2),
            Some(&Scalar::constant64(512).into())
        )
        .is_ok());
    assert!(v
        .check_arg_type(
            &ArgumentType::DynamicMemory(2),
            Some(&Scalar::constant64(1024).into())
        )
        .is_err());
}
