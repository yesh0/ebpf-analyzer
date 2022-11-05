# Undecidable Programs

eBPF is not [Turing-complete](https://en.wikipedia.org/wiki/Turing_completeness),
nor can any verifier validate a Turing-complete language:
the [halting problem](https://en.wikipedia.org/wiki/Halting_problem) is undecidable.

Therefore, the verifier can reject totally regular programs,
requiring the programmer to adjust to it.

## Failing snippets

Some snippets that failed verification on Linux 5.19 are listed below.

`data_end` and `data` marks the packet content received by an XDP filter.

- The pointer `data` is reported as out of bound.
  ```c
  for (int i = 0; i < data_end - data; i++) {
      if (((char *) data)[i] == -1) {
          return XDP_PASS;
      }
  }
  ```

- The pointer `p` is reported as out of bound.
  ```c
  for (char *p = data; p < data_end; p++) {
      if (*p == -1) {
          return XDP_PASS;
      }
  }
  ```

- The loop is reported as "infinite" with `clang -O0`, possibly due to misaligned spilled values.
  ```c
  int result = 0;
  for (int i = 0; i < 0x10; i++) {
      result += i;
  }
  ```
  I managed to reproduce this with the following eBPF assembly:
  ```
  xdp_prog_simple:
      r1 = 0
      *(u32 *)(r10 - 4) = r1     # Spilled
      goto LBB0_1
  LBB0_1:
      r1 = *(u32 *)(r10 - 4)     # Restore
      if r1 s> 32767 goto LBB0_2
      r1 += 1
      *(u32 *)(r10 - 4) = r1     # Spilled
      goto LBB0_1
  LBB0_2:
      r0 = r1
      exit
  ```
  It works fine if the spilled value is 64-bit aligned.

