# Overview

## How actually an eBPF program is run

::: warning
The following description may differ from the actual implementation in Linux or libbpf.
:::

### Kernel space
1. eBPF programs are passed into the kernel with the [`BPF(2)`](./user/syscall.md) syscall,
   which mainly contains the following info:
   - Program type, license, version, size...
   - The raw program, or rather, an array of eBPF instructions
   - Optionally some debug info
2. The instructions are checked by the verifier.
3. Things (e.g., pointers to maps) are relocated.
4. If JIT compilation is enabled, the JIT module compiles the instructions into native code.
5. A file descriptor is allocated for the eBPF program.
6. Upon running, either
   - the interpreter interprets the instructions,
   - or the compiled native code runs directly.
   - (We allocate a new stack frame for each function call.)

### User space (with libbpf)

1. The user writes the eBPF program in C.
2. LLVM compiles the source into eBPF instructions,
   saving them into an ELF file along with relocation information, debug information, etc.
3. Libbpf reads in the ELF file, parses it, and acts according to section names:
   - Some maps are configured.
   - BPF programs are adjusted with BTF info from the kernel to ensure [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/).
   - Things (jump destinations, for example) are relocated.
   - The programs are submitted to the kernel with the `BPF(2)` syscall.

### Variations

Yes, eBPF is ever evolving.
It does seem that kernel developers are moving relocations from libbpf into the kernel
so that the compiled eBPF instructions stay immutable.
See [some notes on the syscall interface](./user/syscall.md#bpf-prog-load).
