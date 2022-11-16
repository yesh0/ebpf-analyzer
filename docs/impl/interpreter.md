# eBPF Interpreter Implementation

The Linux interpreter lies here:
[`kernel/bpf/core.c#___bpf_prog_run`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/core.c#L1643)

To understand what exactly each instruction means and their undefined behaviors,
given that no documentation ever states that (for now),
we have to look into an actual, official implementation.

| Ops / Variant   | Code                                                     | Notes              |
|-----------------|----------------------------------------------------------|--------------------|
| Shifts (64-bit) | `DST = DST OP (SRC & 63)`                                |                    |
| Shifts (32-bit) | `DST = (u32) DST OP ((u32) SRC & 31)`                    | Upper-half zeroed  |
| Shifts (s64)    | `(*(s64 *) &DST) >>= (SRC & 63)`                         |                    |
| Shifts (s32)    | `DST = (u64) (u32) (((s32) DST) >> (SRC & 31))`          | Upper-half zeroed  |
| ALU (64-bit)    | `DST = DST OP SRC`                                       | `+ - & \| ^ *`     |
| ALU (32-bit)    | `DST = (u32) DST OP (u32) SRC`                           | Upper-half zeroed  |
| ALU (NEG64)     | `DST = -DST`                                             |                    |
| ALU (NEG32)     | `DST = (u32) -DST`                                       | Upper-half zeroed  |
| ALU (MOV64)     | `DST = SRC`                                              |                    |
| ALU (MOV32)     | `DST = (u32) SRC`                                        | Upper-half zeroed  |
| ALU (MOV_K 64)  | `DST = (__s32) IMM`                                      | Sign-extending     |
| `LD_IMM_DW`     | See [`LD_IMM_DW`](../user/spec.md)                       |                    |
| MOD (64-bit)    | `div64_u64_rem(DST, SRC, &AX); DST = AX;`                | Unknown            |
| MOD (32-bit)    | `AX = (u32) DST; DST = do_div(AX, (u32) SRC);`           | Unknown            |
| DIV (64-bit)    | `DST = div64_u64(DST, SRC)`                              | Unknown            |
| DIV (32-bit)    | `AX = (u32) DST; do_div(AX, (u32) SRC); DST = (u32) AX;` | Unknown            |
| Endianness      | `DST = (__force u??) cpu_to_be??(DST)`                   | Upper bits zeroed  |
| Function calls  | Pre-processed by the verifier. Skipping.                 |                    |
| JMP             | `insn += insn->off`                                      | `+1` by outer loop |
| Conditional JMP | `if ((SIGN##64) DST CMP_OP (SIGN##64) SRC) { ... }`      | Casts              |
| STX             | `*(SIZE *)(unsigned long) (DST + insn->off) = SRC`       | Casts              |
| ST              | `*(SIZE *)(unsigned long) (DST + insn->off) = IMM`       | Casts?             |
| LDX             | `DST = *(SIZE *)(unsigned long) (SRC + insn->off)`       | Casts              |
| Atomic          | ...                                                      | WIP                |

## Notes

Note that the interpreter implementation is not necessarily the actual specification.
