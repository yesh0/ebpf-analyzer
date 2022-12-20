static long (*as_is)(int i) = (void*) 2;

int main() {
  long long p = as_is(0);
  for (int i = 0; i != 100; ++i) {
    if (i == 99) {
      *((char *) ((void *) p)) = 0;
    }
  }
  return 0;
}
