static long long (*as_is)(long long i) = (void*) 2;

int main() {
  int i = as_is(34);
  long long l = as_is(0x0FFFFFFF00000000);
  for (int j = 0; j < i; j++) {
    l = -l >> 1;
    if (((unsigned int) l) % 2 == 1) {
      goto exit;
    }
  }
 exit:
  return (int) (l & 0xFFFF);
}
