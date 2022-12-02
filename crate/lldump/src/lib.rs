//! This crate is a mess, containing all kinds of utilities for tests.

pub mod helper;
pub mod conformance;

fn from_bytes(s: &[&str], i: usize) -> u64 {
    let mut result = 0;
    let mut shift = 0;
    for c in s.iter().skip(i).take(8) {
        let v = u8::from_str_radix(c, 16).ok().unwrap();
        result |= (v as u64) << shift;
        shift += 8;
    }
    result
}

pub fn parse_llvm_dump(s: &str) -> Vec<u64> {
    let mut output: Vec<u64> = Vec::new();
    s.split('\n')
        .filter(|line| !line.contains("file format elf64-bpf") && line.contains(":\t"))
        .for_each(|line| {
            let line: Vec<&str> = line.split('\t').collect();
            let bytes: Vec<&str> = line[1].split(' ').collect();
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
#[should_panic]
fn test_illegal_dump() {
    parse_llvm_dump("LineNumber:\t1 2 3 4");
}
