static long (*assert)(long i) = (void*) 2;
static long (*as_is)(long i) = (void*) 2;
static long (*bpf_trace_printk)(const char *fmt, unsigned int fmt_size, ...) = (void *)6;

int main() {
  char hello[] = "Hello    World\n";
  // valid call
  bpf_trace_printk(hello, sizeof(hello));

  // LLVM allocates aligned space on stack,
  // which means "Hello World\n" is actually "Hello World\n\0\0\0" on stack,
  // and `bpf_trace_printk("Hello World\n", 16)` is totally valid despite its 13-byte size.
  assert(sizeof(hello) == 16);
  long i = as_is(0xFFFF00000100);
  hello[5] = (char) as_is('!');
  if (((int) i) < 0x1000) {
    bpf_trace_printk(hello, sizeof(hello) + 1);
  } else {
    bpf_trace_printk(hello, sizeof(hello) * 2);
  }
  return 0;
}