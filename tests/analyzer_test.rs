use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, VerificationError},
    branch::{checked_value::CheckedValue, vm::BranchState},
    interpreter::vm::Vm,
    spec::proto::{ArgumentType, IllegalFunctionCall, StaticFunctionCall, VerifiableCall},
    track::{scalar::Scalar, TrackedValue},
};
use llvm_util::parse_llvm_dump;

pub const LOOP_OK: &str = include_str!("bpf-src/loop-ok.txt");
pub const LOOP_NOT_OK: &str = include_str!("bpf-src/loop-not-ok.txt");
pub const LOOP_OK_BUT: &str = include_str!("bpf-src/large-loop.txt");
pub const LOOP_BRANCH_OK: &str = include_str!("bpf-src/branching-loop.txt");

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
        // nop
        &StaticFunctionCall::new([
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
            ArgumentType::Any,
        ]),
        // assertion
        &AssertFunc {},
        // as-is
        &AsIsFunc {},
    ],
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
