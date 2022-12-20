static long (*assert)(long i) = (void*) 1;
static long (*as_is)(long i) = (void*) 2;

int main() {
  long long p = as_is(0);
  unsigned long long limit = as_is(100);
  unsigned int end = as_is(1000);
  // Create an unknown number
  end = end / 7;
  // Set an upper limit
  if (0 <= end && end < limit) {
    for (int i = 0; i < end; ++i) {
      if (i == 100) {
        *((char *) (void *) p) = 0;
      } else {
        assert(i < 100);
      }
    }
  }
  return 0;
}
