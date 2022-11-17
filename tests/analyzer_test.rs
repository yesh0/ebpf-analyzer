use ebpf_analyzer::{analyzer::{Analyzer, VerificationError}};
use llvm_util::parse_llvm_dump;

pub const LOOP_OK: &str = include_str!("bpf-src/loop-ok.txt");
pub const LOOP_NOT_OK: &str = include_str!("bpf-src/loop-not-ok.txt");
pub const LOOP_OK_BUT: &str = include_str!("bpf-src/large-loop.txt");

#[test]
fn test_ok_loop() {
    let code = parse_llvm_dump(LOOP_OK);
    match Analyzer::analyze(&code) {
        Ok(_) => {},
        Err(VerificationError::IllegalStateChange(branch)) => {
            panic!("{:?}", branch);
        },
        Err(err) => panic!("Err: {:?}", err),
    }
}

#[test]
fn test_not_ok_loop() {
    let code = parse_llvm_dump(LOOP_NOT_OK);
    match Analyzer::analyze(&code) {
        Ok(_) => panic!("Err"),
        Err(err) => std::println!("Error captured: {:?}", err),
    }
}

#[test]
fn test_costly() {
    let code = parse_llvm_dump(LOOP_OK_BUT);
    match Analyzer::analyze(&code) {
        Ok(_) => {},
        Err(err) => panic!("Error captured: {:?}", err),
    }
}
