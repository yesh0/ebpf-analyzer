static int (*as_is)(int i) = (void*) 2;

int main() {
  long long p = as_is(0);
  int limit = as_is(100);
  for (int i = 0; i != limit; ++i) {
    if (i == 99) {
      p += 1;
    }
    if (i == 100) {
      *((char *) ((void *) p)) = 0;
    }
  }
  return 0;
}