use std::{cell::RefCell, rc::Rc};

use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, VerificationError},
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::vm::Vm,
    spec::proto::{
        ArgumentType, IllegalFunctionCall, ResourceOperation, ReturnType, StaticFunctionCall,
        VerifiableCall,
    },
    track::{
        pointees::{dyn_region::DynamicRegion, struct_region::StructRegion},
        pointer::{Pointer, PointerAttributes},
        scalar::Scalar,
        TrackedValue,
    },
};
use llvm_util::parse_llvm_dump;

struct AssertFunc;

impl VerifiableCall<CheckedValue, BranchState> for AssertFunc {
    fn call(&self, vm: &mut BranchState) -> Result<CheckedValue, IllegalFunctionCall> {
        match vm.ro_reg(1).inner() {
            Some(TrackedValue::Scalar(s)) => {
                if s.contains(0) {
                    panic!("{s:?}")
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
    processed_instruction_limit: 40_000_000,
    helpers: &[
        // (0) nop
        &StaticFunctionCall::new(
            [
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::None,
        ),
        // (1) assertion
        &AssertFunc {},
        // (2) as-is
        &AsIsFunc {},
        // (3) allocates resource 1
        &StaticFunctionCall::new(
            [
                ArgumentType::Scalar,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::AllocatedResource(1),
        ),
        // (4) uses resource 1
        &StaticFunctionCall::new(
            [
                ArgumentType::ResourceType((1, ResourceOperation::Unknown)),
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::None,
        ),
        // (5) deallocates resource 1
        &StaticFunctionCall::new(
            [
                ArgumentType::ResourceType((1, ResourceOperation::Deallocates)),
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::None,
        ),
        // (6) printk
        &StaticFunctionCall::new(
            [
                ArgumentType::DynamicMemory(2),
                ArgumentType::Scalar,
                ArgumentType::Any,
                ArgumentType::Any,
                ArgumentType::Any,
            ],
            ReturnType::None,
        ),
    ],
    setup: &|vm| {
        let region = Rc::new(RefCell::new(DynamicRegion::default()));
        vm.add_external_resource(region.clone());
        let pointer = Pointer::new(
            PointerAttributes::NON_NULL
                | PointerAttributes::ARITHMETIC
                | PointerAttributes::READABLE,
            region.clone(),
        );
        let end = Pointer::end(region);
        let context = Rc::new(RefCell::new(StructRegion::new(
            vec![pointer, end],
            &[1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2],
        )));
        vm.add_external_resource(context.clone());
        *vm.reg(1) = Pointer::new(
            PointerAttributes::NON_NULL | PointerAttributes::READABLE,
            context,
        )
        .into();
    },
};

macro_rules! define_test {
    ($name:ident, $file:expr, $result:pat, $dump:block) => {
        #[test]
        fn $name() {
            let code = parse_llvm_dump(include_str!($file));
            match Analyzer::analyze(&code, &HELPERS) {
                $result => $dump
                Err(err) => panic!("Err: {:?}", err),
                #[allow(unreachable_patterns)]
                _ => panic!("Expecting failed invalidation"),
            }
        }
    };
}

define_test!(test_ok_loop, "bpf-src/loop-ok.txt", Ok(_), {});
define_test!(
    test_not_ok_loop,
    "bpf-src/loop-not-ok.txt",
    Err(VerificationError::IllegalStateChange(branch)),
    { std::println!("Captured: {branch:?}") }
);

define_test!(test_branching, "bpf-src/branching-loop.txt", Ok(_), {});
define_test!(test_costly, "bpf-src/large-loop.txt", Ok(_), {});
define_test!(
    test_fail_costly,
    "bpf-src/larger-loop.txt",
    Err(VerificationError::IllegalContext(context)),
    { std::println!("Captured: {context}") }
);

define_test!(test_dyn_region, "bpf-src/dynamic-range.txt", Ok(_), {});
define_test!(
    test_dyn_region_fail,
    "bpf-src/dynamic-fail.txt",
    Err(VerificationError::IllegalStateChange(branch)),
    { std::println!("Captured: {branch:?}") }
);

define_test!(test_resource_ok, "bpf-src/resource-ok.txt", Ok(_), {});
define_test!(
    test_resource_fail,
    "bpf-src/resource-fail.txt",
    Err(VerificationError::IllegalStateChange(branch)),
    { std::println!("Captured: {branch:?}") }
);

define_test!(test_printk, "bpf-src/printk.txt", Ok(_), {});
define_test!(
    test_printk_fail,
    "bpf-src/printk-fail.txt",
    Err(VerificationError::IllegalStateChange(branch)),
    { std::println!("Captured: {branch:?}") }
);
