# Conditional Jump Verification

Our implementation differs from the verifier in Linux.

## Range Narrowing

The eBPF verifier should use conditional jump information to narrow down the range of possible values.
For example, evaluating the following code `goto (A <= B) ? branch_1 : branch_2;`,
the verifier can use the extra condition `A <= B` after jumping to `branch_1`,
and apply `A > B` for `branch_2`.

The main difference is that we handle range comparisons like $A \leqslant B$ and $A \gt B$,
while Linux seems to handle only comparison against a constant number.

### Handling the `A ⩽ B` branch

Let $A = [a_{\min}, a_{\max}], B = [b_{\min}, b_{\max}]$.

We are to narrow down the ranges assuming that $A \leqslant B$.

1. If $a_{\max} \leqslant b_{\min}$, since $a \leqslant b$ is always true,
   we can extract no extra info.
2. If $b_{\max} \lt a_{\min}$, then $a \leqslant b$ is never true
   and the execution flow should never reach here.

Otherwise, let $I = A \cap B = [i_{\min}, i_{\max}]$,
where $i_{\min} = \max \{ a_{\min}, b_{\min} \}$,
and $i_{\max} = \min \{ a_{\max}, b_{\max} \}$.
$I$ is never empty.

We can then narrow down the ranges into:

$$
A^{\dagger} = [a_{\min}, i_{\max}],
$$

$$
B^{\dagger} = [i_{\min}, b_{\max}].
$$

You can verify it by:
- letting $a' = b' \in I$ (necessity),
- and trying $a' = i_{\max} + 1$ or $b' = i_{\min} - 1$ (sufficiency).

So the above result is the best estimate we can ever deduce.

### Handling the `A > B` branch

It is a little bit more complex.

See the section above for handling these two condition:
- $a_{\max} \leqslant b_{\min}$,
- $b_{\max} \lt a_{\min}$.

Otherwise, again, let $I = A \cap B = [i_{\min}, i_{\max}]$.
The narrowed-down ranges are as follows:

<style>
.content table {
  width: fit-content;
  margin: auto;
}
</style>

| Condition                | $A^{\dagger}$              | $B^{\dagger}$              |
|--------------------------|----------------------------|----------------------------|
| $i_{\min} \neq b_{\min}$ | $[i_{\min}, a_{\max}]$     |                            |
| $i_{\min} = b_{\min}$    | $[i_{\min} + 1, a_{\max}]$ |                            |
| $i_{\max} \neq a_{\max}$ |                            | $[b_{\min}, i_{\max}]$     |
| $i_{\max} = a_{\max}$    |                            | $[b_{\min}, i_{\max} - 1]$ |

Summing up:
$$
A^{\dagger} = [\max\{a_{\min}, b_{\min}+1\}, a_{\max}],
$$
$$
B^{\dagger} = [b_{\min}, \min\{b_{\max}, a_{\max}-1\}].
$$

It should be fairly easy to understand why it is so:
- since $A \gt B \implies B \leqslant A$, following the section above, we have:
  - $B^{\dagger} \subseteq [b_{\min}, i_{\max}]$,
  - $A^{\dagger} \subseteq [i_{\min}, a_{\max}]$.

- Sufficiency:
  $A \gt B \implies$ $b_{\min} \notin A^{\dagger},$ $a_{\max} \notin B^{\dagger}$,
- Necessity: verifier against $b = i_{\max} - 1$ or $a = i_{\min} + 1$ should be enough.

Note that $a_{\max} \gt b_{\min}$ and the ranges above are always valid.
