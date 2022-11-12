use ebpf_analyzer::{
    analyzer::{Analyzer, VerificationError},
    spec::{Instruction, ParsedInstruction}, blocks::FunctionBlock,
};

pub const SIMPLE1: &str = include_str!("bpf-src/simple-1.txt");
pub const SIMPLE2: &str = include_str!("bpf-src/simple-2.txt");

fn from_bytes(s: &Vec<&str>, i: usize) -> u64 {
    let mut result = 0;
    let mut shift = 0;
    for j in i..i + 8 {
        let v = u8::from_str_radix(s[j], 16).ok().unwrap();
        result |= (v as u64) << shift;
        shift += 8;
    }
    result
}

pub fn parse_llvm_dump(s: &str) -> Vec<u64> {
    let mut output: Vec<u64> = Vec::new();
    s.split("\n")
        .filter(|line| !line.contains("file format elf64-bpf") && line.contains(":\t"))
        .for_each(|line| {
            let line: Vec<&str> = line.split("\t").collect();
            let bytes: Vec<&str> = line[1].split(" ").collect();
            if bytes.len() == 8 {
                output.push(from_bytes(&bytes, 0));
            } else if bytes.len() == 16 {
                output.push(from_bytes(&bytes, 0));
                output.push(from_bytes(&bytes, 8));
            } else {
                panic!("Unrecognized llvm dump");
            }
        });
    output
}

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
                    panic!("Invalid code[{}]: {:?}: {:?}", pc, err, i);
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
    match FunctionBlock::new(&code) {
        Ok(blocks) => assert!(blocks[0].block_count() == 10, "Block count does not match"),
        Err(err) => panic!("Err: {:?}", err),
    }
    match Analyzer::analyze(&code) {
        Ok(_) => {},
        Err(err) => panic!("Err: {:?}", err),
    }
}

#[test]
fn validate_unreachable_blocks() {
    let code = parse_llvm_dump(SIMPLE2);
    match Analyzer::analyze(&code) {
        Ok(_) => panic!("Should contains unreachable blocks"),
        Err(err) => assert!(err == VerificationError::IllegalGraph),
    }
}
