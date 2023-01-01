use ebpf_consts::*;
use opcode_macros::opcode_match;

#[test]
pub fn match_test() {
    println!("{}", match_number(BPF_ALU | BPF_X | BPF_ADD));
    assert!(match_number(BPF_ALU | BPF_X | BPF_ADD) == 0xFFFFFFFF);
    assert!(match_number(BPF_ALU | BPF_X | BPF_RSH) == 0);
    assert!(match_number(BPF_ALU | BPF_X | BPF_LSH) == 0);
}

pub fn match_number(opcode: u8) -> u64 {
    println!("{opcode:#x}");
    opcode_match! {
        opcode,
        [[BPF_ALU: ALU, BPF_ALU64: ALU64], [BPF_X: X, BPF_K: K],
        [
            BPF_ADD: "+",
            BPF_AND: "&",
            BPF_OR : "|",
            BPF_XOR: "^",
            BPF_LSH: "<<",
            BPF_RSH: ">>",
         ]] => {
            let dst = 0xFFF00FFF0000u64;
            #?((X))   let src = 0x000FF000FFFFu64; ##
            #?((K))   let src = 0u64;              ##
            #?((ALU)) let src = src as u32;        ##
            #?((ALU))
                let dst = dst as u32;
            ##
            #?(("<<")|(">>"))
                let limit = #?((ALU)) 31 ## #?((ALU64)) 63 ##;
                let src = src & limit;
            ##
            let res = dst #=2 src;
            let s = #2;
            println!("Expr: {dst:#x} {s} {src:#x}");
            res #?((ALU)) as u64 ##
        }
        _ => {
            let v = vec![0, 1, 2];
            v[0]
        }
    }
}

#[test]
fn test_replacing_in_parenthesis() {
    let opcode = 0u8;
    let values = vec![1, 2, 3, 4];
    let value = opcode_match! {
        opcode as u8 in ebpf_consts,
        [[BPF_ADD: "+"]] => {
            // (1 + 2) * 3 -> 9
            let value = (1 #=0 2) * 3;
            // 9 + (10 + 10)
            value + if values[1 #=0 2] == 4 {
                10 #=0 10
            } else {
                0
            }
        }
        _ => {
            0
        }
    };
    assert_eq!(value, 29);
}

#[test]
fn test_multiple_aliases() {
    let opcode = 0u8;
    assert_eq!(
        opcode_match! {
            opcode as u8 in ebpf_consts,
            [[BPF_ADD: [1, 2, 3, 4, 5]]] => {
                #:0:=0 * (#:1:=0 + #:2:=0 + #:3:=0) * #:4:=0
            }
            _ => 0,
        },
        45
    );
}

#[test]
fn test_with_same_aliases() {
    mod consts {
        pub const A: u8 = 0;
        pub const B: u8 = 1;
    }
    for i in 0u8..2 {
        opcode_match! {
            i as u8 in consts,
            [[A: ["do_a", "do_final"], B: ["do_b", "do_final"]]] => {
                #?((!do_final)) panic!(); ##
                #?((do_final))
                    assert_eq!(#:1:0, "do_final");
                    assert!(#0.starts_with("do_"));
                ##
            }
            _ => panic!(),
        }
    }
}
