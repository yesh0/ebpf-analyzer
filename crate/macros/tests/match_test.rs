use ebpf_macros::opcode_match;
use ebpf_consts::*;

#[test]
pub fn match_test() {
    println!("{}", match_number(BPF_ALU | BPF_X | BPF_ADD));
    assert!(match_number(BPF_ALU | BPF_X | BPF_ADD) == 0xFFFFFFFF);
    assert!(match_number(BPF_ALU | BPF_X | BPF_RSH) == 0);
    assert!(match_number(BPF_ALU | BPF_X | BPF_LSH) == 0);
}

pub fn match_number(opcode: u8) -> u64 {
    println!("{:#x}", opcode);
    opcode_match! {
        opcode,
        [[BPF_ALU: ALU, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
        [
            BPF_ADD: "+",
            BPF_SUB: "-",
            BPF_AND: "&",
            BPF_OR : "|",
            BPF_XOR: "^",
            BPF_MUL: "*",
            BPF_LSH: "<<",
            BPF_RSH: ">>",
         ]] => {
            let dst = 0xFFF00FFF0000u64;
            #?((X))   let src = 0x000FF000FFFFu64; ##
            #?((K))   let src = 0u64;              ##
            #?((ALU)) let src = src as u32;        ##
            #?((ALU))
                let dst = dst as u32;
                #?(("<<")|(">>"))
                    let src = src & 31;
                ##
            ##
            let res = dst #=2 src;
            let s = #2;
            println!("Expr: {:#x} {} {:#x}", dst, s, src);
            res as u64
        }
        _ => {
            let v = vec![0, 1, 2];
            v[0]
        }
    }
}
