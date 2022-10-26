# The syscall

Reading [the syscall documentation](https://docs.kernel.org/userspace-api/ebpf/syscall.html) is a direct way to learn about it.
An alternative is [`man 2 bpf`](https://man7.org/linux/man-pages/man2/bpf.2.html) but it can miss some info.

Also, you can have a look at the Linux source code:
- [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L1300)
  is where you can find the definition of `union bpf_attr`.
- [`kernel/bpf/syscall.c`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/kernel/bpf/syscall.c#L4911)
  contains all accepted `cmd` codes.

## `BPF_PROG_LOAD`

This command consumes a rather complex `bpf_attr`, which is poorly documented.
You might want to check out [libbpf](./libbpf.md#a-source-code-reading-list) to see how the command is used in action.

```c
// https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L1358-L1393
struct { /* anonymous struct used by BPF_PROG_LOAD command */
    __u32		prog_type;	/* one of enum bpf_prog_type */ // [!code hl]
    __u32		insn_cnt;
    __aligned_u64	insns; // [!code hl]
    __aligned_u64	license;
    __u32		log_level;	/* verbosity level of verifier */
    __u32		log_size;	/* size of user buffer */
    __aligned_u64	log_buf;	/* user supplied buffer */
    __u32		kern_version;	/* not used */
    __u32		prog_flags; // [!code hl]
    char		prog_name[BPF_OBJ_NAME_LEN];
    __u32		prog_ifindex;	/* ifindex of netdev to prep for */
    /* For some prog types expected attach type must be known at
    * load time to verify attach type specific parts of prog
    * (context accesses, allowed helpers, etc).
    */
    __u32		expected_attach_type; // [!code hl]
    __u32		prog_btf_fd;	/* fd pointing to BTF type data */ // [!code hl]
    __u32		func_info_rec_size;	/* userspace bpf_func_info size */
    __aligned_u64	func_info;	/* func info */ // [!code hl]
    __u32		func_info_cnt;	/* number of bpf_func_info records */
    __u32		line_info_rec_size;	/* userspace bpf_line_info size */
    __aligned_u64	line_info;	/* line info */ // [!code hl]
    __u32		line_info_cnt;	/* number of bpf_line_info records */
    __u32		attach_btf_id;	/* in-kernel BTF type id to attach to */
    union {
        /* valid prog_fd to attach to bpf prog */
        __u32		attach_prog_fd; // [!code hl]
        /* or valid module BTF object fd or 0 to attach to vmlinux */
        __u32		attach_btf_obj_fd; // [!code hl]
    };
    __u32		core_relo_cnt;	/* number of bpf_core_relo */
    __aligned_u64	fd_array;	/* array of FDs */ // [!code hl]
    __aligned_u64	core_relos; // [!code hl]
    __u32		core_relo_rec_size; /* sizeof(struct bpf_core_relo) */
};
```

I am not to explain all this mess. But anyway,
- `prog_type`: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L940-L981):
  Unfortunately you can hardly find any documentation on what each type means.
  You may find some introduction from the Internet, like:
  - [uhh, the kernel documentation?](https://docs.kernel.org/bpf/programs.html)
  - [or this article at LWN](https://lwn.net/Articles/740157/)
  - [or this tour from Oracle Linux Blog](https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types)

  But to stay up-to-date, you will need to `git blame` through the code and find the culprit commit (no offence).

- `insns`: The eBPF instructions. The most comprehensible part of this struct.

- `prog_flags`: It is some random bit flags……
  You may find the possible flags and documentation at [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L1048-L1154).
- `expected_attach_type`: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L983-L1029)
  (sigh)
- `prog_btf_fd`: A file descriptor from with `BPF_BTF_LOAD`.
- `func_info`, `line_info`: BTF info. See [BPF Type Format (BTF)](https://docs.kernel.org/bpf/btf.html#bpf-prog-load) for more info.
- `attach_prog_fd`: The file descriptor for _another eBPF program_. See [this commit](https://github.com/torvalds/linux/commit/5b92a28aae4dd0f88778d540ecfdcdaec5a41723).
- `attach_btf_obj_fd`: Please refer to [this commit](https://github.com/torvalds/linux/commit/290248a5b7d829871b3ea3c62578613a580a1744).
- `fd_array`: Uhh, relocation data. Please refer to [this commit](https://github.com/torvalds/linux/commit/387544bfa291a22383d60b40f887360e2b931ec6).
- `core_relos`: Uhh, relocation data.
  Please refer to [this commit](https://github.com/torvalds/linux/commit/fbd94c7afcf99c9f3b1ba1168657ecc428eb2c8d)
  and [these comments](https://github.com/torvalds/linux/blob/4dc12f37a8e98e1dca5521c14625c869537b50b6/include/uapi/linux/bpf.h#L6930-L6983).

  By the way, while `core_relo_cnt` goes before `fd_array`, it has nothing to do with that. All is about padding.

  (And I just don't understand why a note got placed in the commit message instead of comments.)
