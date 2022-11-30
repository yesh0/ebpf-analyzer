# Function Call Verification

## Helper Function Verification

[`check_helper_call`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L7233-L7631)
checks whether the current program is permitted to call the helper function
and validates the parameters passed to that function.

First it acquires a `bpf_func_proto` from the verifier environment,
as is defined in [`include/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf.h#L563-L602).
In summary, `bpf_func_proto` contains the following:
- a function pointer to that very function,
- license terms (GPL or not),
- packet access,
- argument information (types and BTF ids or sizes),
- return value info,
- and a customized function pointer for extra validation.

::: info
Packet data seems to be transient, and such pointers need special processing,
as per [the comments here](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c#L6566-L6568):

```c
/* Packet data might have moved, any old PTR_TO_PACKET[_META,_END]
 * are now invalid, so turn them into unknown SCALAR_VALUE.
 */
```
:::

Then the verifier ensures that:
- the caller is license compatible with the helper function;
- the caller passes the customized extra validation
  (seemingly disallowing probe programs from accessing some helpers for now);
- the arguments conform;
- the helper is used _correctly_, for example,
  - not writing a map marked as `BPF_F_RDONLY_PROG`,
  - or not reading / modifying unused stack slots,
  - (as well as not violating several function specific checks);
- caller saved registers are marked as invalid;
- `R0` is set to something matching the return value of the helper.

## `bpf_func_proto`

Here is a few examples:

- [`bpf_get_current_task`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/trace/bpf_trace.c#L762):

  ```c
  const struct bpf_func_proto bpf_get_current_task_proto = {
      .func         = bpf_get_current_task,
      .gpl_only     = true,
      .ret_type     = RET_INTEGER,
  };
  ```

  And here is a typical usage:

  ```c
  // From https://nakryiko.com/posts/bpf-core-reference-guide/#bpf-core-read
  struct task_struct *task = (void *)bpf_get_current_task();
  struct task_struct *parent_task;
  int err;

  err = bpf_core_read(&parent_task, sizeof(void *), &task->parent);
  if (err) {
    /* handle error */
  }

  /* parent_task contains the value of task->parent pointer */
  ```

- [`bpf_probe_read_user_str`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/trace/bpf_trace.c#L216):

  ```c
  const struct bpf_func_proto bpf_probe_read_user_str_proto = {
      .func         = bpf_probe_read_user_str,
      .gpl_only     = true,
      .ret_type     = RET_INTEGER,
      .arg1_type    = ARG_PTR_TO_UNINIT_MEM,
      .arg2_type    = ARG_CONST_SIZE_OR_ZERO,
      .arg3_type    = ARG_ANYTHING,
  };
  ```
