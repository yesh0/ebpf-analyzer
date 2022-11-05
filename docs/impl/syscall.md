# Syscall Entrance

## `BPF_PROG_LOAD`

Processed by [`bpf_prog_load`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/syscall.c#L2463-L2655), which:

1. Checks the permission, the flags, license compatibility;
2. Initializes a `struct bpf_prog`;
3. Runs the verifier with [`bpf_check`](../verifier/verifier.md);
4. Tries to JIT the program with `bpf_prog_select_runtime`;
5. Allocates an ID to the program, and maybe calls `bpf_prog_kallsyms_add` (no idea what it does).

<!-- TODO: Find out what `bpf_prog_kallsyms_add` does (seemingly adding the program to a list of kernel symbols) -->
