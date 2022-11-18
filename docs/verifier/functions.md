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
