static void *(*new_resource)(long i) = (void *)3;
static void (*use_resource)(void *i) = (void *)4;
static void (*del_resource)(void *i) = (void *)5;

#define COUNT (512 / 8 - 1)

int main() {
  void *resources[COUNT];
  for (int i = 0; i != COUNT; ++i) {
    resources[i] = new_resource(i);
  }
  for (int i = COUNT; i > 0; --i) {
    use_resource(resources[i - 1]);
    del_resource(resources[i - 1]);
  }
  return 0;
}