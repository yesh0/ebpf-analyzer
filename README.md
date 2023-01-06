# ebpf-analyzer

[![Licensed under MIT](https://img.shields.io/github/license/yesh0/ebpf-analyzer)](./LICENSE)
[![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/yesh0/ebpf-analyzer/test.yml?branch=main)](https://github.com/yesh0/ebpf-analyzer/actions/workflows/test.yml)
[![Codecov](https://img.shields.io/codecov/c/gh/yesh0/ebpf-analyzer)](https://app.codecov.io/gh/yesh0/ebpf-analyzer)


This is a WIP eBPF verifier.

## Architecture

The verifier mostly follows the Linux eBPF verifier.

1. It scans through the eBPF byte code, searching for any invalid instructions, i.e.,
   - unrecognized instructions,
   - instructions with non-zero unused instructions,
   - instructions with invalid fields (like invalid register fields),
   - etc.
2. It scans through the eBPF byte code, producing a control-flow graph.
   - The graph includes edges from:
     - function calls,
     - and jump instructions.
3. Based on the control-flow graph, it checks for unreachable code and rejects the program
   if it finds any.
   - It should also forbid function recursion, but the current implementation does not
     check that.
4. It simulates execution of the program and rejects it if it finds any potentially
   malicious action.

### Simulation

The most work lies in the simulation part.

I would describe the simulation code as a specialized eBPF interpreter.
- Value tracking:
  - For normal eBPF interpreters, each register is a `u64` value, tracking its precise value.
  - For our verifier, each register is a `TrackedValue`, tracking its possible values.
- Pointer tracking: Similar to pointer concepts in interpreters, we tracks a pointer with
  the following properties:
  - the memory region that it points to,
  - pointer attributes like nullability or mutability,
  - offset, etc.
- Stack:
  - For normal eBPF interpreters, the stack is the memory region pointed to by `R10`.
  - For our verifier it is mostly the same, with the stack *trying* to keep track of values
    on stack to allow for more precise value tracking when a value is spilled.
- Instruction execution:
  - For normal eBPF interpreters, they read from registers, operate on them, and maybe write
    values back to registers.
  - For our verifier, we read from registers, operate on them, and maybe update
    the `TrackedValue` with an updated set of possible values.
    Also, if we find values in the registers suspicious, we just reject the program.
- Jump execution:
  - For normal eBPF interpreters, they compare the precise values in the registers,
    and modify a `PC` variable according to the comparison result.
  - For our verifier, we compare our `TrackedValue`s. If we are uncertain of the comparison
    result, we *branch* to make sure that all possibilities are checked.
    - State pruning is not yet implemented.

Main API:
- `ebpf_analyzer::analyzer::Analyzer::analyze(...)`: The analyzer
- `ebpf_analyzer::analyzer::AnalyzerConfig`: The config, where you specify how you expect
  the program to behave.

  Using config struct requires direct manipulation of the inner VM state and is not that
  user-friendly. Improvements are on the way.

Important `struct`s:
- `CheckedValue`: A value that can get invalidated when a forbidden operation occurs,
  wrapping `TrackedValue`.
  - `TrackedValue`: A value that is either `Scalar` or `Pointer`.
    - `Scalar`: A scalar value, tracking possible values and known bits.
    - `Pointer`: A pointer, pointing to somewhere relative to the base of a memory region.
      - `trait MemoryRegion`: Memory regions or resource representations.
- `trait Context`: Simulation context, tracking branches and possibly pruning status.
- `trait Vm`: The VM.

## To do list

The verifier implementation is not yet complete, missing quite a few pieces.

### Missing verifier features

- State pruning: necessary in order to speed up complex program verification

- Per program configuration:
  - Allow using pointers as scalars for *some* programs

- More built-in types:
  - In principle, users can actually implement this by themselves as a user-defined type.
  - Built-in types:
    - Map in maps

- Map-related `IMM64` instruction support:
  - Currently we support `MAP_FD` and `MAP_VALUE`.

- Memory regions with variable lengths:
  - Currently, we implement them as a `DynamicRegion`.
    However, such regions in Linux involves invalidation - regions seem to get
    invalidated after some access to it. And we should implement that.

- Tests:
  - Against more complex programs, for example, those in
    [ebpf-samples](https://github.com/vbpf/ebpf-samples/)
  - Fuzzing

### Library API

For program verification:

- We should try to support most of eBPF program types used by the Linux kernel,
  while offering a customize-able yet easy-to-use API.

The Linux eBPF verifier does much more than simply verifying the program.

- Memory access redirection: In Linux, access to `struct __sk_buff` is redirected
  to the actual `struct sk_buff`, by rewriting the memory access instructions.

  As a verifier (or an analyzer) library, we should not want to modify the code (in place).
  Instead, we would like to provide these info back to the user, and maybe provide a
  separate library to do these work.

- Relocation: rewriting specialized `IMM64` instructions into normal ones.

- Stack usage info: how much stack space does a certain eBPF function requires?
  This should be really helpful for JIT compilers (and interpreters too).
