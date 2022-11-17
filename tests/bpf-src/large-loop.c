int main() {
  long long p = 0;
  for (int i = 0; i != 2000; ++i) {
    for (int j = 0; j != 2000; ++j) {
      if (i == 2000 && j == 2000) {
        *((char *) ((void *) p)) = 0;
      }
    }
  }
  return 0;
}