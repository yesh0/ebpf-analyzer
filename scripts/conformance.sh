#!/bin/sh

# Generate conformance data from https://github.com/Alan-Jowett/bpf_conformance
# We are using it for our tests, so not bothering writing a plugin.

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <build_dir> <output_dir> <custom_test_dir>"
  exit 1
fi

mkdir -p "$2"

if ! [[ -d "$1" ]]; then
  # TODO: Switch to the official repository once things get fixed
  git clone https://github.com/yesh0/bpf_conformance.git "$1"
fi
if ! [[ -d "$1/build" ]]; then
  mkdir -p "$1/build"
  cmake -S "$1" -B "$1/build"
fi
cmake --build "$1/build"

runner="$1/build/bin/bpf_conformance_runner"
output_dir="$2"

gen_test() {
  base=$(basename "$1")
  output=$(realpath "$output_dir/$base.txt")
  echo "$1 => $output"
  # Extracts license info
  grep "^#" "$1" > "$output"
  # Appends contents
  $runner --test_file_path "$1"     \
          --plugin_path /bin/true   \
          --debug true >> "$output"  \
          2>&1 || true
}

for test in "$1/tests"/*; do
  gen_test "$test"
done

for test in "$3"/*.data; do
  gen_test "$test"
done
