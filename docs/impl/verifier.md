---
outline: deep
---

# eBPF Verifier

This will be a really lengthy one.

You can get an impression of the internals of a verifier from:
- [The kernel documentation](https://docs.kernel.org/bpf/verifier.html)
- [and this LWN post](https://lwn.net/Articles/794934/).

## `bpf_check`

[`bpf_check`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L15159)
is where the verification process starts.

It starts by checking `bpf_verifier_ops`- a handcrafted [_virtual method table_](https://en.wikipedia.org/wiki/Virtual_method_table) thing
that binds different data types to their verification functions.

Then it does some allocation and initializes a `struct bpf_verifier_env`.

`bpf_get_btf_vmlinux` initializes kernel BTF info.

The most of the work happens here:

```c
// https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L15245-L15279
	ret = add_subprog_and_kfunc(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_subprogs(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_btf_info(env, attr, uattr);
	if (ret < 0)
		goto skip_full_check;

	ret = check_attach_btf_id(env);
	if (ret)
		goto skip_full_check;

	ret = resolve_pseudo_ldimm64(env);
	if (ret < 0)
		goto skip_full_check;

	if (bpf_prog_is_dev_bound(env->prog->aux)) {
		ret = bpf_prog_offload_verifier_prep(env->prog);
		if (ret)
			goto skip_full_check;
	}

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	ret = do_check_subprogs(env);
	ret = ret ?: do_check_main(env);

	if (ret == 0 && bpf_prog_is_dev_bound(env->prog->aux))
		ret = bpf_prog_offload_finalize(env);
```

Let's take them down one by one.

### `add_subprog_and_kfunc`

This function does the following:

1. Extract all "subprogs" from the eBPF instructions.

   By "subprog" we actually mean an eBPF function, as is in [`BPF_PSEUDO_CALL`](../user/spec.md#function-calls).
   We will try to find the PC to their first instruction for each one.

   - The "main" subprog starts at `insn[0]`.
   - Each `BPF_PSEUDO_CALL` denotes an eBPF function.
   - Each `BPF_PSEUDO_FUNC` relocation denotes an eBPF function. (See [`resolve_pseudo_ldimm64`](#resolve-pseudo-ldimm64).)

   The verifier assumes and [ensures](#check-subprogs) that instructions in one function are consecutive,
   that is, the following _pseudo assembly_ is not allowed:

   ```
   func1:
       ...
       jmp func1_part2
   func2:
       ret
   func1_part2:
       ret
   ```

   Therefore, we can easily locate the boundaries of a function:
   
   ```
   func1: // start of func1
       ...
   func2: // start of func2, end of func1
       ...
   exit:  // end of the whole program, end of func2
   ```

   It adds a fake "exit" subprog to the list, denoting the end of the last function.

2. Extract all "kfunc" calls. (See [`BPF_PSEUDO_KFUNC_CALL`](../user/spec.md#function-calls).)

### `check_subprogs`

`check_subprogs` checks subprogs :P

1. Ensure that jump instructions are within bounds
   (i.e., that it does not jump from one subprog to another).
2. Ensures that one subprog does not "fall through" to another
   by ensuring that it ends with a `BPF_EXIT` or a proper jump.
3. Checks whether a subprog contains certains instructions and sets some flags accordingly:
   - tail calls,
   - `BPF_IND` or `BPF_ABS` instructions.

### `check_btf_info`

Checks BTF info.

BTF info is optional for most eBPF programs,
unless they contains tail calls or `BPF_ABS / BPF_IND` instructions.

### `check_attach_btf_id`

(WIP) <!-- TODO: What on earth -->

### `resolve_pseudo_ldimm64`

Just read [these comments for this function](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L12733-L12739)
and [these comments for these macros](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L1156-L1199).

::: info
Why are these types of relocation done in kernel space instead of user space?

Well, the verifier needs these extra info to know what exactly lies in one register slot.
Otherwise, all of these pseudo instructions translate into a single type-less `LD_IMM64` instruction,
and the verifier has to treat them as scalar values and forbid using them as pointers.
```
mov_map_ptr R1, map_1      // typed insn
mov         R1, 0xdeadbeef // type-less

mov_func    R1, func1      // typed insn
mov         R1, 0xcafebabe // type-less
```
:::

### `check_cfg`

Checks if there are unreachable instructions.
(No, it cannot detect those wrapped with `if (0) { ... }`.

### `do_check_subprogs`

Checks each subprog if BTF info is present.

Notice that it calls `do_check_common`, which eventually calls [`do_check`](#do-check).

### `do_check_main`

Just calls `do_check_common`, which eventually calls [`do_check`](#do-check).

### `do_check_common`

Prepares a `struct bpf_verifier_state` and calls [`do_check`](#do-check).

For subprogs with BTF info, it sets up the state according to the types of their arguments.

## `do_check`

[`kernel/bpf/verifier.c#do_check`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L12144-L12483):
The central part of the verifier where it does most of the work.

If you have skimmed through the interpreter implementation, you will find that,
despite being significantly more complex, `do_check` is quite similar to the interpreter:
an outer loop, `switch`-like dispatching (one uses a dispatching table, while the other is `if-else`).

While it contains _only_ hundreds of lines of code,
you can count on it to just lead you to the other _10k lines_ of code,
which is rather beyond my reach (yet).

<!-- TODO: Do the impossible -->

### `check_alu_op`

This functions checks ALU operations (32-bit & 64-bit).

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

#### `adjust_*_min_max_vals`

##### Precise value tracking

Precise value tracking was introduced in this comment:
[bpf: precise scalar_value tracking](https://github.com/torvalds/linux/commit/b5dc0163d8fd78e64a7e21f309cf932fda34353e).

You should read through the commit message to grasp the gist and what each function does.

Also, I am quoting from [a comment in a LWN article](https://lwn.net/Articles/795367/):
it seems that the verifier always keeps the precise values,
and marking a value as being "precise" just prevents it getting pruned? I am not sure.

##### `adjust_scalar_min_max_vals`

(WIP) <!-- TODO: Uhh... -->
