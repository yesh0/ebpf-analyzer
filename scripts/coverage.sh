#!/bin/sh

mkdir -p target/profile

echo "=== Incremental testing ==="

CARGO_INCREMENTAL=0                                          \
RUSTFLAGS='-Cinstrument-coverage'                            \
LLVM_PROFILE_FILE='target/profile/cargo-test-%p-%m.profraw'  \
cargo test --workspace

echo "=== Generating report ==="

grcov . --binary-path ./target/debug/deps/ -s . -t lcov      \
--branch --ignore-not-existing --ignore '../*' --ignore "/*" \
-o target/coverage/tests.lcov
