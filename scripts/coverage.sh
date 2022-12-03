#!/bin/sh

PROF_DIR="target/profile"
COVERAGE_DIR="target/coverage"
mkdir -p "$COVERAGE_DIR"
mkdir -p "$PROF_DIR"

echo "=== Incremental testing ==="

RUSTFLAGS="-Zprofile             \
           -Ccodegen-units=1     \
           -Cinline-threshold=0  \
           -Clink-dead-code      \
           -Coverflow-checks=off \
           -Cinstrument-coverage"

CARGO_INCREMENTAL=0                                     \
RUSTFLAGS="$RUSTFLAGS"                                  \
LLVM_PROFILE_FILE="$PROF_DIR/cargo-test-%p-%m.profraw"  \
cargo test --workspace

echo "=== Generating report ==="

grcov . --binary-path ./target/debug/ -s . -t lcov            \
--branch --ignore-not-existing --ignore '../*' --ignore "/*"  \
-o target/coverage/tests.lcov

echo "=== Generating HTML ==="

grcov . --binary-path ./target/debug/ -s . -t html            \
--branch --ignore-not-existing --ignore '../*' --ignore "/*"  \
-o target/coverage/
