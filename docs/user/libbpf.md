# Libbpf

One may think of [libbpf](https://github.com/libbpf/libbpf) as a workflow
to get your eBPF programs compiled and run them across different Linux versions.

It wraps up a lot syscall details and provides a clean user interface:
one compiles their eBPF code into a `.o` file with some headers,
passes the `.o` file to libbpf, and it will automate most of the work.

By reading the source code, you can actually see how each syscall is used and what exactly `bpf_attr` means in that context.

## A source code reading list

- [How to construct a `bpf_attr` for `BPF_PROG_LOAD`](https://github.com/libbpf/libbpf/blob/68e6f83f223ebf3fbf0d94c0f4592e5e6773f0c1/src/bpf.c#L235-L318)
