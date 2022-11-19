# Conditional Jump Tracking

[`do_check`](./verifier.md#do-check) calls
[`check_cond_jmp_op`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L10117)
to update tracked values and diverge the execution path.

::: info
Among `JMP/JMP32` opcodes, there are some other instructions:
- `BPF_CALL`: [Function calls](./functions.md)
- `BPF_EXIT`: Returns
- `BPF_JA`: Unconditional jumps

[Verifying them](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L12360-L12450) is done elsewhere.
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

## Register state propagation

Sometimes you have too many variables in your program and the compiler has to spill them onto the stack.
(Or if you are using `clang -O0`, then all variables are allocated on the stack by default.)

Now consider the following scenario (in pseudo eBPF assembly):

```
call func1             # return values is stored in r0
*(u64*)(r10 - 8) = r0  # spilling r0 onto stack
...                    # doing other stuff
r1 = *(u64*)(r10 - 8)  # getting the value back
if r1 > 1000 goto +20  # conditional jump
```

We know that `r1 = *(u64*)(r10 - 8)`.
So if `r1 > 1000`, we believe `*(u64*)(r10 - 8) > 100` holds as well.
The eBPF verifier puts some effort into passing these information around by doing the following:

1. Assign each value a unique id;
   - The id is generated from `++env->id_gen`.
     Since the verifier limits the number of total instructions in a verification branch,
     we should be safe from overflowing the `u32` field.
2. Pass the id on when copying values;
3. Clear the id field each time the value gets changed.

Read the source code for more information:
- [`bpf_verifier.h#bpf_for_each_spilled_reg`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf_verifier.h#L347):
  The verifier walks through the whole allocated stack for spilled registers.
- [`bpf_verifier.h#bpf_for_each_reg_in_vstate`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf_verifier.h#L353):
  A macro to iterate through all register values (including spilled ones).
- [`struct bpf_verifier_env`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf_verifier.h#L507):
  The `id_gen` field is used to generate unique ids for values and pointers.
  (You can search for `++env->id_gen` in `verifier.c` for its usages.
- [`verifier.c#find_equal_scalars`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L10105-L10115):
  Propagates a value to registers of the same id.
