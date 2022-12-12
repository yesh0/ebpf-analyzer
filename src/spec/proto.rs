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
    /// Rejected, either not implemented or not allowed
    Rejected,
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

    /// Returns a function `() -> scalar`
    pub const fn scalar_getter() -> StaticFunctionCall {
        StaticFunctionCall {
            arguments: [
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            returns: ReturnType::Scalar,
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

/// The module defines some commonly used helper function prototypes.
pub mod helpers {
    use crate::track::pointees::map_resource::{MapDeleteCall, MapLookupCall, MapUpdateCall};

    use super::*;

    /// An invalid helper
    pub struct InvalidCall;

    impl VerifiableCall<CheckedValue, BranchState> for InvalidCall {
        fn call(&self, _vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
            Err(IllegalFunctionCall::Rejected)
        }
    }

    /// A helper function that accepts [ArgumentType::Any] and returns [ReturnType::None]
    pub const BPF_HELPER_NOP: &StaticFunctionCall = &StaticFunctionCall::nop();

    /// An invalid helper [InvalidCall]
    pub const BPF_HELPER_INVALID: &InvalidCall = &InvalidCall {};

    /// A helper function `(writable pointer, read size, unsafe pointer) -> error code`
    pub const BPF_HELPER_PROBE_READ: &StaticFunctionCall = &StaticFunctionCall::new(
        [
            ArgumentType::DynamicMemory(2),
            ArgumentType::Scalar,
            ArgumentType::Some,
            ArgumentType::Any,
            ArgumentType::Any,
        ],
        ReturnType::Scalar,
    );

    /// A helper function `() -> scalar`
    pub const BPF_HELPER_GET_SCALAR: &StaticFunctionCall = &StaticFunctionCall::scalar_getter();

    /// A helper function [BPF_HELPER_GET_SCALAR]
    pub const BPF_HELPER_KTIME_GET_NS: &StaticFunctionCall = BPF_HELPER_GET_SCALAR;

    /// A helper function [BPF_HELPER_GET_SCALAR]
    pub const BPF_HELPER_GET_PRANDOM_U32: &StaticFunctionCall = BPF_HELPER_GET_SCALAR;

    /// A helper function [BPF_HELPER_GET_SCALAR]
    pub const BPF_HELPER_GET_SMP_PROCESSOR_ID: &StaticFunctionCall = BPF_HELPER_GET_SCALAR;

    /// A helper function [BPF_HELPER_GET_SCALAR]
    pub const BPF_HELPER_GET_CURRENT_PID_TGID: &StaticFunctionCall = BPF_HELPER_GET_SCALAR;

    /// A helper function [BPF_HELPER_GET_SCALAR]
    pub const BPF_HELPER_GET_CURRENT_UID_GID: &StaticFunctionCall = BPF_HELPER_GET_SCALAR;

    /// A helper function `(writable pointer, read size, ...) -> error code`
    pub const BPF_HELPER_DYN2: &StaticFunctionCall = &StaticFunctionCall::new(
        [
            ArgumentType::DynamicMemory(2),
            ArgumentType::Scalar,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ],
        ReturnType::Scalar,
    );

    /// A helper function [BPF_HELPER_DYN2]
    pub const BPF_HELPER_TRACE_PRINTK: &StaticFunctionCall = BPF_HELPER_DYN2;

    /// A helper function [BPF_HELPER_DYN2]
    pub const BPF_HELPER_GET_CURRENT_COMM: &StaticFunctionCall = BPF_HELPER_DYN2;

    /// The `bpf_map_lookup_elem` helper function
    pub const BPF_HELPER_MAP_LOOKUP_ELEM: &MapLookupCall = &MapLookupCall {};

    /// The `bpf_map_update_elem` helper function
    pub const BPF_HELPER_MAP_UPDATE_ELEM: &MapUpdateCall = &MapUpdateCall {};

    /// The `bpf_map_delete_elem` helper function
    pub const BPF_HELPER_MAP_DELETE_ELEM: &MapDeleteCall = &MapDeleteCall {};

    /// A typical helper collection for [crate::analyzer::Analyzer]
    pub const HELPERS: &[&dyn VerifiableCall<CheckedValue, BranchState>; 17] = &[
        BPF_HELPER_INVALID,
        BPF_HELPER_MAP_LOOKUP_ELEM,
        BPF_HELPER_MAP_UPDATE_ELEM,
        BPF_HELPER_MAP_DELETE_ELEM,
        BPF_HELPER_PROBE_READ,
        BPF_HELPER_KTIME_GET_NS,
        BPF_HELPER_TRACE_PRINTK,
        BPF_HELPER_GET_PRANDOM_U32,
        BPF_HELPER_GET_SMP_PROCESSOR_ID,
        // TODO: Support skb
        BPF_HELPER_INVALID,
        BPF_HELPER_INVALID,
        BPF_HELPER_INVALID,
        // TODO: Support tail call
        BPF_HELPER_INVALID,
        BPF_HELPER_INVALID,
        BPF_HELPER_GET_CURRENT_PID_TGID,
        BPF_HELPER_GET_CURRENT_UID_GID,
        BPF_HELPER_GET_CURRENT_COMM,
    ];
}
