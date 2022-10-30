# Instruction Set Specification

The ["eBPF Instruction Set Specification, v1.0"](https://docs.kernel.org/bpf/instruction-set.html) is outdated and incomplete.
Although eBPF is not strictly versioned, it does seem that it is far beyond "v1.0".

This page aims to be a "diff" between that spec and current kernel implementation.

## Architecture

- The stack / frame: In terms of eBPF, a stack pointer is just a frame pointer.
  Each eBPF function call has its own 512-byte stack.
- `R10`: This registers points to the base of the stack,
  that is, the very end of the stack range (`R10[-512 : 0]`).

## Instruction Encoding

Instructions are encoded in host endianness.

### Wide instructions

A wide instruction is a 128-bit instruction:

```
| 64-bit insn1 | 64-bit insn2 |
```

While the spec states "the wide instruction encoding... appends a second 64-bit immediate value (imm64)
after the basic instruction for a total of 128 bits", it is not.

Actually, `insn1.imm32` is the lower 32 bits and `insn2.imm32` is the upper 32 bits:
[`___bpf_prog_run#LD_IMM_DW`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/core.c#L1738).

```
imm64 = insn1.imm32 | (insn2.imm32 << 32);
```

## Instructions

### Arithmetic and jumps

- `BPF_NEG`: No, this opcode is not a bitwise-not as the spec states: `dst = ~src`.
  [It is actually just `DST = -DST;`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/core.c#L1719-L1724)
  and has nothing to do with the `src` register.
  
- `BPF_DIV`, `BPF_MOD`: An implementation must check for zero divisions.
  In Linux, they just rewrite that instruction into several, with explicit hard-coded zero checks.

- In jump instructions, the `off` (offset) is `(current_jump_insn_pc + 1) - target_pc`,
  which is quite straightforward though.

### Function calls

The eBPF interpreter/JIT compilers in Linux rely on preprocessing in the verifier.
In order to understand how actually function calls work, you will need to get down to the verifier:
[`kernel/bpf/verifier.c#do_misc_fixups`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L13893-L14412)

In short, `BPF_CALL` has multiple semantics, differentiated by the `src_deg` field:

- Calling a [helper function](https://docs.kernel.org/bpf/helpers.html).
  - The `src_reg` field in the instruction must be zeroed.
  - During [`do_misc_fixups`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L14378-L14389),
    the `imm32` field (which originally contains an ID to the helper function) is replaced with a function pointer relative to `__bpf_call_base`.

- Calling one of [BPF Kernel Functions (kfuncs)](https://docs.kernel.org/bpf/kfuncs.html), which requires JIT compilation.
  - The `src_reg` field must be `BPF_PSEUDO_KFUNC_CALL`.
  - During [`fixup_kfunc_call`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L13868-L13891),
    the `imm32` field is replaced similar to helper function calls.

- Doing a `BPF_PSEUDO_CALL`:
  - The `src_reg` field must be `BPF_PSEUDO_CALL`.
  - It is just a relative function call. A libbpf example:
    ```c {3}
    SEC("some_sec")
    int handle(void *ctx) {
      my_func(); // BPF_PSEUDO_CALL
      return 0;
    }
    SEC("some_sec")
    void my_func() {
      bpf_printk("Pseudo-called\n");
    }
    ```
    A new stack frame is allocated for each call.
  - During [`bpf_patch_call_args`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/core.c#L2067-L2074),
    the instruction is replaced with an internal one (`JMP_CALL_ARGS`).
    
::: tip
If you are implementing your own eBPF runtime, you don't need to follow the internals of Linux.
All the above explanations just aim to help with reading Linux source code and understanding eBPF semantics.
:::

### Relocation

(WIP) <!-- TODO: Try to explain this mess -->
