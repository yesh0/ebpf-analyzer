# Prelude

## Who this documentation is for

Most literature on the Internet documents eBPF from a user's perspective.
However, for _**OS developers**_ or someone _**who just needs to write an eBPF implementation**_ from scratch for whatever reason,
they will most likely have to turn to the Linux source code due to a lack of documentation.

This site is an attempt to provide some implementation details of eBPF in Linux,
in the hope that it will pick up some hitchhikers on the way.

## Prerequisites

I assume that you have already heard about eBPF as well as the following concepts before:

- [eBPF instruction set](https://docs.cilium.io/en/latest/bpf/#instruction-set)
  - eBPF virtual machine
  - eBPF byte code
- [eBPF helper functions](https://docs.kernel.org/bpf/helpers.html)
- eBPF interpreter
- [eBPF verifier](https://docs.kernel.org/bpf/verifier.html)
- [Reduced Instruction Set Computer (RISC)](https://en.wikipedia.org/wiki/Reduced_instruction_set_computer)
- [Just-In-Time (JIT) compilation](https://en.wikipedia.org/wiki/Just-in-time_compilation)
- [Ahead-Of-Time (AOT) compilation](https://en.wikipedia.org/wiki/Ahead-of-time_compilation)
- [Relocation](https://en.wikipedia.org/wiki/Relocation_(computing))

We will get to these concepts soon.

### JIT or AOT

We are not going to distinguish between JIT and AOT. But it can be fun if you think about it:

- From the user's perspective, the kernel does JIT compilation, since the compilation is done after they requests to run the program.
- As for eBPF implementers, it is actually AOT: compilation is done before running the code.
  - No, we are not to discuss those complex techniques used by Java or C#.
  - It might eventually evolve into a JIT implementation, but personally I think it is just too slow during warm-up and not worth the price.
