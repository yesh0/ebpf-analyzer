use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig, VerificationError},
    blocks::ProgramInfo,
    spec::{Instruction, ParsedInstruction},
};
use llvm_util::parse_llvm_dump;

pub const SIMPLE1: &str = include_str!("bpf-src/simple-1.txt");
pub const SIMPLE2: &str = include_str!("bpf-src/asm/simple-2.txt");

#[test]
fn validate_valid_code() {
    let code = parse_llvm_dump(SIMPLE1);
    let mut pc = 0usize;
    while pc < code.len() {
        match Instruction::from(&code, pc) {
            ParsedInstruction::None => panic!("Unrecognized"),
            ParsedInstruction::Instruction(i) => {
                assert!(!i.is_wide(), "Wide instruction mismatched");
                if let Err(err) = i.validate() {
                    panic!("Invalid code[{pc}]: {err:?}: {i:?}");
                }
                pc += 1;
            }
            ParsedInstruction::WideInstruction(i) => {
                assert!(i.instruction.is_wide(), "Wide instruction mismatched");
                assert!(i.instruction.validate().is_err());
                assert!(i.validate().is_ok());
                pc += 2;
            }
        }
    }
}

#[test]
fn validate_valid_blocks() {
    let code = parse_llvm_dump(SIMPLE1);
    match ProgramInfo::new(&code) {
        Ok(info) => assert!(
            info.functions[0].block_count() == 8,
            "Block count does not match: {}",
            info.functions[0].block_count()
        ),
        Err(err) => panic!("Err: {err:?}"),
    }
    assert!(matches!(
        Analyzer::analyze(&code, &AnalyzerConfig::default()),
        Err(VerificationError::IllegalContext(_))
    ));
}

#[test]
fn validate_unreachable_blocks() {
    let code = parse_llvm_dump(SIMPLE2);
    match Analyzer::analyze(&code, &AnalyzerConfig::default()) {
        Err(VerificationError::IllegalGraph) => {}
        _ => panic!("Should contain unreachable blocks"),
    }
}
