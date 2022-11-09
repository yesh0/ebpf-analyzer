# Conditional Jump Tracking

[`do_check`](./verifier.md#do-check) calls
[`check_cond_jmp_op`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L10117)
to update tracked values and diverge the execution path.

::: info
Among `JMP/JMP32` opcodes, there are some other instructions:
- `BPF_CALL`: Function calls
- `BPF_EXIT`: Returns
- `BPF_JA`: Unconditional jumps

[Verifying them](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L12360-L12450) is easier.
:::

## `check_cond_jmp_op`

Some straightforward checks:
- Disallowing pointer comparison unless `allow_ptr_leaks` is on.

(WIP)
