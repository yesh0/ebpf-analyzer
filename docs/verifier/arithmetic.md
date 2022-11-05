# Arithmetic Operation Verification

[`do_check`](./verifier.md#do-check) calls `check_alu_op` to check arithmetic operations and update tracked values.

## `check_alu_op`

> This functions checks ALU operations (32-bit & 64-bit):
> 1. Checks non arithmetic operations: `BPF_END`, `BPF_NEG` and `BPF_MOV`;
> 2. Dispatches arithmetic verification to `adjust_reg_min_max_vals`.

Some of the checks done in this function:
1. Reserved fields must be zeroed.
2. Some pointer operations are prohibited:
   - All pointer arithmetic
     - Pointer subtraction is not strictly checked (i.e., the result is marked as unknown)
       and is only allowed if `allow_ptr_leaks`.
   - Partial copy of a pointer
3. `R10` is not writable while uninitialized registers are not readable.
   (See [`check_reg_arg`](https://github.com/torvalds/linux/blob/23758867219c8d84c8363316e6dd2f9fd7ae3049/kernel/bpf/verifier.c#L2449).)
4. Division by zero or undefined shifts (e.g., `u64 << 65`) are prohibited.

Side effects:
1. Register status update: `mark_reg_scratched`, `mark_reg_read`, `mark_reg_unknown`.
2. Instance mark: `mark_insn_zext`.
3. Register scalar value update: `adjust_reg_min_max_vals`, which calls `adjust_scalar_min_max_vals`.
4. Register pointer value update: `adjust_ptr_min_max_vals`.

| `src` \ `dst` | Pointer                      | Scalar                       |
|---------------|------------------------------|------------------------------|
| Pointer       | Forbidden unless subtracting | `adjust_ptr_min_max_vals`    |
| Scalar        | `adjust_ptr_min_max_vals`    | `adjust_scalar_min_max_vals` |

### Precise value tracking

Precise value tracking was introduced in this comment:
[bpf: precise scalar_value tracking](https://github.com/torvalds/linux/commit/b5dc0163d8fd78e64a7e21f309cf932fda34353e).

You should read through the commit message to grasp the gist and what each function does.

Also, I am quoting from [a comment in a LWN article](https://lwn.net/Articles/795367/):
it seems that the verifier always keeps the precise values,
and marking a value as being "precise" just prevents it getting pruned? I am not sure.

### `adjust_scalar_min_max_vals`

This function dispatches operations to:
- `scalar_min_max_add`: Addition
- `scalar_min_max_sub`: Subtraction
- `scalar_min_max_mul`: Multiplication
- `scalar_min_max_and`: Bit-wise AND
- `scalar_min_max_or`: Bit-wise OR
- `scalar_min_max_xor`: Bit-wise XOR
- `scalar_min_max_lsh`: Left shift
- `scalar_min_max_rsh`: Right shift (unsigned)
- `scalar_min_max_arsh`: Right shift (sign bit extending)

Basically they update the `tnum` field and the min/max fields of a scalar:
```c
// https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf_verifier.h#L147-L166
struct bpf_reg_state {
  // ...
  /* For scalar types (SCALAR_VALUE), this represents our knowledge of
   * the actual value.
   * For pointer types, this represents the variable part of the offset
   * from the pointed-to object, and is shared with all bpf_reg_states
   * with the same id as us.
   */
  struct tnum var_off;
  /* Used to determine if any memory access using this register will
   * result in a bad access.
   * These refer to the same value as var_off, not necessarily the actual
   * contents of the register.
   */
  s64 smin_value; /* minimum possible (s64)value */
  s64 smax_value; /* maximum possible (s64)value */
  u64 umin_value; /* minimum possible (u64)value */
  u64 umax_value; /* maximum possible (u64)value */
  s32 s32_min_value; /* minimum possible (s32)value */
  s32 s32_max_value; /* maximum possible (s32)value */
  u32 u32_min_value; /* minimum possible (u32)value */
  u32 u32_max_value; /* maximum possible (u32)value */
  // ...
};
```

If ever you would like to peek into the implementation details,
here are some notes:

1. Before dispatching, `adjust_scalar_min_max_vals` tries to:
   - Validate the register state (in case of `min_value > max_value`);
   - Ensure `src_known` for some opcodes (e.g., shifts), or set the register as unknown;
   - Sanitize something that is probably part of branch tracking or pruning...

   `adjust_scalar_min_max_vals` has undergone refactoring,
   which moved portions of it out into functions like `scalar(32)_min_max_...`.
   When reading the processing logic in `scalar(32)_min_max_...`,
   you should always take note that some of these functions require `src_known`,
   that is, **some of them assume that `src_reg` is a constant**.

2. In that big `switch` block in `adjust_scalar_min_max_vals`:
   - For some opcodes, `dst_reg->var_off` is changed before calling `scalar(32)_min_max_...`;
     - These opcodes are `BPF_ADD` and `BPF_SUB`,
       whose `scalar(32)_min_max_...` functions are independent of `dst_reg->var_off`.
   - For some other opcodes, `dst_reg->var_off` is assigned after calling `scalar(32)_min_max_...`;
   - Shifts assign to `dst_reg->var_off` inside `scalar(32)_min_max_...`.

3. The actual logic inside `scalar(32)_min_max_...` functions:
   - Bit-wise operations (`and`, `or`, `xor`) are quite straightforward.
   - For `add`, `sub` and `mul`, uh, you might want to check out this essay:
     [\[arXiv:2105.05398\] Sound, Precise, and Fast Abstract Interpretation with Tristate Numbers](https://arxiv.org/abs/2105.05398).
   - For shifts, things are quite easy
     if you bear in mind that they require a **constant `src_reg`**.

(WIP) <!-- TODO: Uhh... -->
