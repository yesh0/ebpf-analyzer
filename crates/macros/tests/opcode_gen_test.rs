#[cfg(test)]
mod codes {
    use opcode_macros::opcode_gen;

    opcode_gen! {
        for BPF_* in ebpf_consts as u8 {
            [
                [BPF_ALU, BPF_ALU64],
                [BPF_X, BPF_K],
                [BPF_ADD, BPF_SUB, BPF_MUL],
            ]
        }
    }
}

#[test]
fn test_opcode_gen() {
    use ebpf_consts::*;
    assert_eq!(codes::BPF_ALU64_K_ADD, BPF_ALU64 | BPF_K | BPF_ADD)
}
