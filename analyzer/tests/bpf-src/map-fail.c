static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, long long flags) = (void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;

int main() {
  // Our test utils will transform this into a map fd imm64 load
  // Just for testing purpose
  void *map = (void *) 0x000DEADCAFE00810;
  long long key = 0xDEADBEEF0000CAFE;
  char value[16];
  for (int i = 0; i != 16; i++) {
    value[i] = 0;
  }
  bpf_map_update_elem(map, &key, value, 0);
  char *v = (char *) bpf_map_lookup_elem(map, &key);
  if (v != 0) {
    for (int i = 0; i != 16; i++) {
      value[i] = v[i];
    }
    bpf_map_update_elem(map, &key, value, 0);
    // v is no longer available
    bpf_map_delete_elem(map, v);
  }
  return 0;
}
