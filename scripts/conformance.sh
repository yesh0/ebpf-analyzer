#!/bin/sh

# Generate conformance data from https://github.com/Alan-Jowett/bpf_conformance
# We are using it for our tests, so not bothering writing a plugin.

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <build_dir> <output_dir>"
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

for test in "$1/tests"/*; do
  base=$(basename "$test")
  output=$(realpath "$2/$base.txt")
  echo "--test_file_path \"$test\" --plugin_path /bin/true --debug true &> \"$output\""
  "$1/build/bin/bpf_conformance_runner" \
              --test_file_path "$test"  \
              --plugin_path /bin/true   \
              --debug true > "$output"  \
              2>&1 || true
done
