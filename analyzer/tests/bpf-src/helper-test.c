// // LLVM will treat nop as null and optimize the supposed-to-fail program to nil.
// static int (*nop)() = (void*) 0;
static int (*as_is)(int i) = (void*) 1;
static void (*putc)(char c) = (void*) 2;

int main() {
  int i = as_is(99);
  if (i < 100) {
    for (int j = 0; j <= i; ++j) {
      putc('a' + (((unsigned int) j) % 26));
    }
  }
  return 0; 
}