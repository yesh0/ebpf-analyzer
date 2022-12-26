# Resources

## Source code

eBPF is always evolving, and obviously the kernel documentation is not following up. To get a better understanding of eBPF, you should always check out the kernel source code.

Don't panic. Linux source code is neat.
- The kernel interpreter:
  - [`kernel/bpf/core.c#___bpf_prog_run`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/core.c#L1643)
- The kernel verifier:
  - [The header at `linux/bpf_verifier.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/linux/bpf_verifier.h)
  - [Most of the code is at `kernel/bpf/verifier.c`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/verifier.c):
    you might want to start reading at the end of the file where `bpf_check` lies.
- The kernel JIT compilers:
  - [Header for riscv64](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/arch/riscv/net/bpf_jit.h)
  - [Code for riscv64](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/arch/riscv/net/bpf_jit_comp64.c)

  The eBPF VM is actually designed to be RISC, so JIT compilers for RISC architectures can be more understandable (provided that you are willing to learn about it).
- The syscall interface:
  - [`kernel/bpf/syscall.c`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/syscall.c)
  - [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h)

::: tip
When reading lengthy code, an IDE really makes your life better.
(I mainly use one to collapse the code I have comprehended.)

Personally I find `github.dev` satisfactory. For any GitHub URL, replacing `github.com` with `github.dev` does the job.
:::

## Kernel documentation

::: tip
Ongoing efforts to update relevant documentation:
- [Update ISA documentation](https://github.com/dthaler/ebpf-docs/pull/4)

  The updated ISA draft lies [here](https://github.com/dthaler/ebpf-docs/blob/update/isa/kernel.org/instruction-set.rst).

- [eBPF.md: Add missing instructions and instruction variants (32-bit jumps, atomic instructions, call and lddw variants)](https://github.com/iovisor/bpf-docs/pull/26)
:::

Despite being a little bit outdated, the kernel documentation documents the gist of some decisions and can give you a vague impression of how things work.
- [The instruction set "specification"](https://docs.kernel.org/bpf/instruction-set.html) is too incomplete to be a spec but can be a good starting point.
- [The verifier documentation](https://docs.kernel.org/bpf/verifier.html) provides an overview of the verifier implementation.
  - The verifier supports some bounded loops now.
    Check out the LWN article [Bounded loops in BPF for the 5.3 kernel](https://lwn.net/Articles/794934/) for more details.
- [An introduction to BTF](https://docs.kernel.org/bpf/btf.html) introduce you to a format
  storing symbol names, function signatures and other debug info.
- [`man 2 bpf`](https://man7.org/linux/man-pages/man2/bpf.2.html) documents some important syscall `cmd`.
- [bpf() subcommand reference](https://docs.kernel.org/userspace-api/ebpf/syscall.html) seems more complete than the previous one.

## Third party documentation

Third party documents and blog are good. Things may change, but the code structure as well as the ABI usually stays the same.

Here is a non-exhaustive list, and you can always search for ones that suit your need.
- [BPF and XDP Reference Guide - Cilium documentation](https://docs.cilium.io/en/latest/bpf/)
- [A series of blog posts about BPF - Oracle Linux Blog](https://blogs.oracle.com/linux/post/bpf-application-development-and-libbpf)
- [Libbpf: A Beginners Guide - ContainIQ](https://www.containiq.com/post/libbpf)
- [Understanding struct \__sk_buff](https://medium.com/@c0ngwang/understanding-struct-sk-buff-730cf847a722): Talks about context access conversion

## eBPF programming

- [XDP Programming Hands-On Tutorial](https://github.com/xdp-project/xdp-tutorial):
  While it focuses on XDP, it covers libbpf usages and some eBPF caveats.
  If you want to take a glimpse into user space eBPF programming (with libbpf),
  this is absolutely a good starting point.

- [The art of writing eBPF programs: a primer.](https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/):
  An introduction to writing eBPF programs attaching to trace points.
