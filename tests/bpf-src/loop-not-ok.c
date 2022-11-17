int main() {
  long long p = 0;
  for (int i = 0; i != 100; ++i) {
    if (i == 99) {
      *((char *) ((void *) p)) = 0;
    }
  }
  return 0;
}