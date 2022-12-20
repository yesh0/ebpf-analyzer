struct region {
  unsigned char *start;
  unsigned char *end;
};

static long (*as_is)(long i) = (void*) 2;

int bpf_main(struct region *context) {
  if (context->start + 0xFF <= context->end) {
    as_is((context->start)[0]);
    as_is((context->start)[0xFF - 1]);
    if (context->end > context->start + 0xFFF) {
      as_is((context->start)[0xFF]);
      as_is((context->start)[0xFFF - 1]);
      // No, for simplicity we treat `ptr1 < ptr2` as `ptr1 <= ptr2`,
      // so you will not be able to do the following just yet
      // as_is((context->start)[0xFFF]);
      if (context->end > context->start + 0xFFF + 1) {
        as_is((context->start)[0xFF]);
        as_is((context->start)[0xFFF - 1]);
        as_is((context->start)[0xFFF]);
        // Fails here
        as_is((context->start)[0xFFF + 1]);
      }
    }
  }
  return 0;
}