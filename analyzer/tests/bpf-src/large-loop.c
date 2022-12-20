static long (*assert)(int i) = (void*) 1;
static long (*as_is)(int i) = (void*) 2;

int main() {
  long long p = as_is(0);
  for (int i = 0; i != 2000; ++i) {
    for (int j = 0; j != 2000; ++j) {
      if (i == 2000 && j == 2000) {
        *((char *) ((void *) p)) = 0;
      } else {
        assert(i - 2000);
      }
    }
  }
  return 0;
}
