int main() {
  long long p = 0;
  unsigned int end = 1000;
  // Create an unknown number
  end = end / 7;
  // Set an upper limit
  if (0 <= end && end < 100) {
    for (int i = 0; i < end; ++i) {
      if (i == 100) {
        *((char *) (void *) p) = 0;
      }
    }
  }
  return 0;
}