//! Function prototype information

use core::ops::RangeInclusive;

use crate::{
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::{value::VmValue, vm::Vm},
    track::{
        pointees::{pointed, simple_resource::SimpleResource, AnyType},
        pointer::Pointer,
        scalar::Scalar,
        TrackError, TrackedValue,
    },
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
    /// Illegal resource (deallocated, for example)
    IllegalResource,
}

/// Function prototype information
pub trait VerifiableCall<Value: VmValue, M: Vm<Value>> {
    /// Verifies the function call
    fn call(&self, vm: &mut M) -> Result<Value, IllegalFunctionCall>;
}

/// Describes what the function do to a resource
#[derive(Clone)]
pub enum ResourceOperation {
    /// Probably unimportant operation
    Unknown,
    /// Deallocates the region
    Deallocates,
}

/// Hard-coded allowed argument types
#[derive(Clone, Default)]
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
    /// Resource pointer (not null, readable & writable)
    ResourceType((AnyType, ResourceOperation)),
}

/// Describes what the function returns
pub enum ReturnType {
    /// Invalid value
    None,
    /// (Unknown) scalar value
    Scalar,
    /// Allocated resource (nullable)
    AllocatedResource(AnyType),
    /// External resource (nullable)
    ExternalResource(AnyType),
}

/// Specifies the arguments
pub type Arguments = [ArgumentType; 5];

/// Verifies the call basing on static information
pub struct StaticFunctionCall {
    arguments: Arguments,
    returns: ReturnType,
}

impl StaticFunctionCall {
    /// Creates a function prototype
    pub const fn new(arguments: Arguments, returns: ReturnType) -> StaticFunctionCall {
        StaticFunctionCall { arguments, returns }
    }

    /// Returns a nop function
    pub const fn nop() -> StaticFunctionCall {
        StaticFunctionCall {
            arguments: [
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            returns: ReturnType::None,
        }
    }
}

impl VerifiableCall<CheckedValue, BranchState> for StaticFunctionCall {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        for i in 1..=5u8 {
            let arg = self.arguments[(i - 1) as usize].clone();
            match arg {
                ArgumentType::FixedMemory(_) => {
                    if vm.is_invalid_resource(i) {
                        return Err(IllegalFunctionCall::IllegalResource);
                    }
                    vm.ro_reg(i).check_arg_type(&arg, None)?;
                }
                ArgumentType::DynamicMemory(reg) => {
                    if vm.is_invalid_resource(i) {
                        return Err(IllegalFunctionCall::IllegalResource);
                    }
                    let (a, b) = vm.two_regs(i, reg).unwrap();
                    a.check_arg_type(&arg, Some(b))?;
                }
                ArgumentType::ResourceType((_, ref op)) => {
                    if vm.is_invalid_resource(i) {
                        return Err(IllegalFunctionCall::IllegalResource);
                    }
                    vm.ro_reg(i).check_arg_type(&arg, None)?;
                    let reg = vm.ro_reg(i);
                    if let ResourceOperation::Deallocates = op {
                        if let Some(TrackedValue::Pointer(p)) = reg.inner() {
                            vm.deallocate_resource(p.get_pointing_to());
                        }
                    }
                }
                _ => {
                    vm.ro_reg(i).check_arg_type(&arg, None)?;
                }
            }
        }
        match self.returns {
            ReturnType::None => Ok(CheckedValue::default()),
            ReturnType::Scalar => Ok(Scalar::unknown().into()),
            ReturnType::AllocatedResource(type_id) => {
                let resource = pointed(SimpleResource::new(type_id));
                vm.add_allocated_resource(resource.clone());
                Ok(Pointer::nrw(resource).into())
            }
            ReturnType::ExternalResource(type_id) => {
                let resource = pointed(SimpleResource::new(type_id));
                vm.add_external_resource(resource.clone());
                Ok(Pointer::nrw(resource).into())
            }
        }
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
    use crate::track::pointees::stack_region::StackRegion;
    let ptr = Pointer::nrw(pointed(StackRegion::default()));
    let v: CheckedValue = ptr.clone().into();
    assert!(v.check_arg_type(&ArgumentType::Any, None).is_ok());
    assert!(v.check_arg_type(&ArgumentType::Scalar, None).is_err());
    assert!(v
        .check_arg_type(&ArgumentType::Constant(0..=100), None)
        .is_err());
    assert!(v
        .check_arg_type(&ArgumentType::FixedMemory(8), None)
        .is_err());
    assert!(ptr.set_all(8).is_ok());
    assert!(v
        .check_arg_type(&ArgumentType::FixedMemory(8), None)
        .is_ok());
    assert!(v
        .check_arg_type(
            &ArgumentType::DynamicMemory(2),
            Some(&Scalar::constant64(512).into())
        )
        .is_err());
    assert!(ptr.set_all(512).is_ok());
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
