# Libbpf

One may think of [libbpf](https://github.com/libbpf/libbpf) as a workflow
to get your eBPF programs compiled and run them across different Linux versions.

It wraps up a lot syscall details and provides a clean user interface:
one compiles their eBPF code into a `.o` file with some headers,
passes the `.o` file to libbpf, and it will automate most of the work.

By reading the source code, you can actually see how each syscall is used and
what exactly `bpf_attr` means in that context.

## A source code reading list

- [How to construct a `bpf_attr` for `BPF_PROG_LOAD`](https://github.com/libbpf/libbpf/blob/68e6f83f223ebf3fbf0d94c0f4592e5e6773f0c1/src/bpf.c#L235-L318)

## Maps

Libbpf provides a convenient way for user to declare and use eBPF maps:

- Declaration:

  ```c
  // Deprecated style (removed in libbpf v1.0)
  struct bpf_map_def SEC("maps") my_map = {
      .type = BPF_MAP_TYPE_ARRAY,
      .max_entries = 1,
      .key_size = sizeof(int),
      .value_size = sizeof(int),
  };
  // BTF style
  struct {
      __uint(type, BPF_MAP_TYPE_ARRAY);
      __uint(max_entries, 1);
      __type(key, int);
      __type(value, int);
  } my_map SEC(".maps");
  ```

- Usage:

  ```c
  int key = 0;
  void *map = &my_map;
  int *value = bpf_map_lookup_elem(&map, &key);
  ```

Pretty convenient. To achieve this, libbpf does some work under the hood:
the (older) Linux kernel only recognizes map descriptors, which programs obtain
by actually creating the map (like file descriptors), so libbpf will have to:

- create all the maps needed by the eBPF program(s),
- and convert all map usages with the map descriptors, e.g.,

  ```c
  // The original code
  void *map = &my_map;
  // The converted code, using map descriptors
  void *map = injected_map_fd;
  ```

  which is part of the relocation process.

Also, to distinguish `void *map = injected_map_fd` from
`long map = (long) injected_map_fd` (which will get rejected by the verifier),
a special kind of instruction is used.

### Global data sections

Introduced in [`d859900c4c56`](https://github.com/torvalds/linux/commit/d859900c4c56dc4f0f8894c92a01dad86917453e).

User space programs can access data in their `.data`, `.rodata` or `.bss`
sections:

```c
// Stored in `.data` section
static int magic = 0x42;
int main() {
  return magic++;
}
// Compiled into
int main() {
  int *magic = runtime_injected_magic_pointer;
  return (*magic)++;
}
```

However, one cannot inject pointers freely in eBPF programs: the eBPF verifier
will need to know about all pointers and user injected ones will very likely get
rejected since they don't look like pointers nor are safe to access.

To provide functionalities similar to `.data` sections:
- map value regions are used as data sections,
- the pointer injection job is moved into the kernel space.

```c
// Stored in `.data` section
static int magic = 0x42;
int main() {
  return magic++;
}
// Compiled into
int main() {
  int *magic = verifier_please_inject_pointer_to_this_map_value(fd, ...);
  return (*magic)++;
}
```

Libbpf will still need to create the maps and inject the map descriptor `fd`.
