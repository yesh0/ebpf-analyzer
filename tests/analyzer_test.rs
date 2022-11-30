use std::{cell::RefCell, rc::Rc};

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, VerificationError},
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::vm::Vm,
    spec::proto::{ArgumentType, IllegalFunctionCall, StaticFunctionCall, VerifiableCall, ReturnType, ResourceOperation},
    track::{
        pointees::{dyn_region::DynamicRegion, struct_region::StructRegion},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
        TrackedValue,
    },
};
use llvm_util::parse_llvm_dump;

pub const LOOP_OK: &str = include_str!("bpf-src/loop-ok.txt");
pub const LOOP_NOT_OK: &str = include_str!("bpf-src/loop-not-ok.txt");
pub const LOOP_OK_BUT: &str = include_str!("bpf-src/large-loop.txt");
pub const LOOP_BRANCH_OK: &str = include_str!("bpf-src/branching-loop.txt");
pub const DYN_OK: &str = include_str!("bpf-src/dynamic-range.txt");
pub const DYN_FAIL: &str = include_str!("bpf-src/dynamic-fail.txt");
pub const RESOURCE_OK: &str = include_str!("bpf-src/resource-ok.txt");
pub const RESOURCE_FAIL: &str = include_str!("bpf-src/resource-fail.txt");

struct AssertFunc;

impl VerifiableCall<CheckedValue, BranchState> for AssertFunc {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        match vm.ro_reg(1).inner() {
            Some(TrackedValue::Scalar(s)) => {
                if s.contains(0) {
                    panic!("{:?}", s)
                }
            }
            _ => panic!("{:?}", vm.ro_reg(1)),
        }
        Ok(Scalar::unknown().into())
    }
}

struct AsIsFunc;

impl VerifiableCall<CheckedValue, BranchState> for AsIsFunc {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        Ok(vm.ro_reg(1).clone())
    }
}

const HELPERS: AnalyzerConfig = AnalyzerConfig {
    helpers: &[
        // (0) nop
        &StaticFunctionCall::new([
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ], ReturnType::None),
        // (1) assertion
        &AssertFunc {},
        // (2) as-is
        &AsIsFunc {},
        // (3) allocates resource 1
        &StaticFunctionCall::new([
            ArgumentType::Scalar,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ], ReturnType::AllocatedResource(1)),
        // (4) uses resource 1
        &StaticFunctionCall::new([
            ArgumentType::ResourceType((1, ResourceOperation::Unknown)),
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ], ReturnType::None),
        // (5) deallocates resource 1
        &StaticFunctionCall::new([
            ArgumentType::ResourceType((1, ResourceOperation::Deallocates)),
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ], ReturnType::None),
    ],
    setup: |vm| {
        let region = Rc::new(RefCell::new(DynamicRegion::default()));
        vm.add_external_resource(region.clone());
        let pointer = Pointer::new(
            PointerAttributes::NON_NULL
                | PointerAttributes::ARITHMETIC
                | PointerAttributes::READABLE,
            region.clone(),
        );
        let end = Pointer::new(
            PointerAttributes::NON_NULL | PointerAttributes::DATA_END,
            region,
        );
        let context = Rc::new(RefCell::new(StructRegion::new(
            vec![pointer, end],
            &[
                1, 1, 1, 1, 1, 1, 1, 1,
                2, 2, 2, 2, 2, 2, 2, 2,
            ],
        )));
        vm.add_external_resource(context.clone());
        *vm.reg(1) = Pointer::new(PointerAttributes::NON_NULL | PointerAttributes::READABLE, context).into();
    },
};

#[test]
fn test_ok_loop() {
    let code = parse_llvm_dump(LOOP_OK);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => {}
        Err(VerificationError::IllegalStateChange(branch)) => {
            panic!("{:?}", branch);
        }
        Err(err) => panic!("Err: {:?}", err),
    }
}

#[test]
fn test_not_ok_loop() {
    let code = parse_llvm_dump(LOOP_NOT_OK);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => panic!("Err"),
        Err(err) => std::println!("Error captured: {:?}", err),
    }
}

#[test]
fn test_branching() {
    let code = parse_llvm_dump(LOOP_BRANCH_OK);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => {}
        Err(err) => panic!("Error captured: {:?}", err),
    }
}

#[test]
fn test_costly() {
    let code = parse_llvm_dump(LOOP_OK_BUT);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => {}
        Err(err) => panic!("Error captured: {:?}", err),
    }
}

#[test]
fn test_dyn_region() {
    let code = parse_llvm_dump(DYN_OK);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => {}
        Err(err) => panic!("Error captured: {:?}", err),
    }
}

#[test]
fn test_dyn_region_fail() {
    let code = parse_llvm_dump(DYN_FAIL);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => panic!(),
        Err(err) => std::println!("Error captured: {:?}", err),
    }
}

#[test]
fn test_resource_ok() {
    let code = parse_llvm_dump(RESOURCE_OK);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => {},
        Err(err) => panic!("Error captured: {:?}", err),
    }
}

#[test]
fn test_resource_fail() {
    let code = parse_llvm_dump(RESOURCE_FAIL);
    match Analyzer::analyze(&code, &HELPERS) {
        Ok(_) => panic!(),
        Err(err) => std::println!("Error captured: {:?}", err),
    }
}
