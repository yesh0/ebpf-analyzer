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

Some important functions that it calls (i.e., those functions that it passes an `opcode` parameter):

- [`is_branch_taken`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L9634):
  According to the comments, it will
  `compute branch direction of the expression "if (reg opcode val) goto target;"`.
- [`reg_combine_min_max`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L9919):
  With `BPF_JEQ` for example, `a == b` means that they share the same set of possible values
  and this can be used to narrow down the their ranges.
- [`reg_set_min_max`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L9728):
  Adjusts the ranges of scalars for branches after comparison like `a < constant` or `a >= constant`, etc.
- [`reg_set_min_max_inv`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L9888):
  Wrapper of `reg_set_min_max` with inverted parameter pair (e.g., `constant > b`).
- [`find_equal_scalars`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L10105):
  Seems to propagate scalar info to other registers that were assigned the same value.

Pointer comparison:

- [`mark_ptr_or_null_regs`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L9980):
  Mark non-null / null pointers.
- [`try_match_pkt_pointers`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L10000):
  Pattern matching packet pointer comparison, gathering packet size info.

Some straightforward checks:
- Disallowing pointer comparison unless `allow_ptr_leaks` is on.

(WIP)
