//! This crate is a mess, containing all kinds of utilities for tests.

pub mod conformance;
pub mod helper;

fn from_bytes(s: &[&str], i: usize) -> u64 {
    let mut result = 0;
    let mut shift = 0;
    for c in s.iter().skip(i).take(8) {
        let v = u8::from_str_radix(c, 16).unwrap();
        result |= (v as u64) << shift;
        shift += 8;
    }
    result
}

/// Parses llvm dump
///
/// It also offers a way to inject map relocations:
/// we transform `ldxdw r1, (0x000DEADCAFE00000 + fd)` into `ldxdw map_fd r1, fd`.
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
                let first = from_bytes(&bytes, 0);
                let second = from_bytes(&bytes, 8);
                if second == (0x000DEADCAFE00000 & 0xFFFF_FFFF_0000_0000) {
                    output.push(0x00001018 | (first & 0xF_FFFF_0000_0F00));
                    output.push(0);
                } else {
                    output.push(first);
                    output.push(second);
                }
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
