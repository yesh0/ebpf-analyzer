static long (*as_is)(long i) = (void*) 2;
static long (*bpf_trace_printk)(const char *fmt, unsigned int fmt_size, ...) = (void *)6;

int main() {
  char hello[] = "Hello World\n";
  long i = as_is(0xFFFF00000100);
  hello[5] = (char) as_is('!');
  if (((int) i) < 0x1000) {
    bpf_trace_printk(hello, sizeof(hello));
  } else {
    bpf_trace_printk(hello, sizeof(hello) * 2);
  }
  return 0;
}