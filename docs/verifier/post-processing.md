# Post-Processing

After the validation, the verifier does several things, rewriting the program bytecode.

```c
https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L15284
if (ret == 0)
    ret = check_max_stack_depth(env);

/* instruction rewrites happen after this point */
if (ret == 0)
    ret = optimize_bpf_loop(env);

// ...

if (ret == 0)
    /* program is valid, convert *(u32*)(ctx + off) accesses */
    ret = convert_ctx_accesses(env);

if (ret == 0)
    ret = do_misc_fixups(env);

// ...

if (ret == 0)
    ret = fixup_call_args(env);

// ...

if (env->used_map_cnt || env->used_btf_cnt) {
    /* program is valid. Convert pseudo bpf_ld_imm64 into generic
     * bpf_ld_imm64 instructions
     */
    convert_pseudo_ld_imm64(env);
}
```

## `check_max_stack_depth`

```c
https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L4219
/* starting from main bpf function walk all instructions of the function
 * and recursively walk all callees that given function can call.
 * Ignore jump and exit insns.
 * Since recursion is prevented by check_cfg() this algorithm
 * only needs a local stack of MAX_CALL_FRAMES to remember callsites
 */
static int check_max_stack_depth(struct bpf_verifier_env *env)
```

## `convert_ctx_accesses`

```c
https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L13399
/* convert load instructions that access fields of a context type into a
 * sequence of instructions that access fields of the underlying structure:
 *     struct __sk_buff    -> struct sk_buff
 *     struct bpf_sock_ops -> struct sock
 */
static int convert_ctx_accesses(struct bpf_verifier_env *env)
```

You might want to check out this article [Understanding struct \__sk_buff](https://scribe.bus-hit.me/@c0ngwang/understanding-struct-sk-buff-730cf847a722),
which explains the conversion a bit.
