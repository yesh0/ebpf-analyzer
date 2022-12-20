static long (*as_is)(int i) = (void*) 2;

int main() {
  unsigned long long p = as_is(0);
  for (unsigned long long i = p; i != 0xFFFFFFFFF; ++i) {
    as_is(i);
  }
  return 0;
}