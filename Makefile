BPF_DIR := tests/bpf-src
BPF_SOURCE := $(BPF_DIR)/%.txt

$(BPF_SOURCE): $(BPF_DIR)/%.c
	clang -target bpf -mcpu=v3 -Wall -O1 -c "$<" -o - | llvm-objdump -r -S - > "$@"

bpf-gen: $(addsuffix .txt, $(basename $(wildcard $(BPF_DIR)/*.c)))

conformance-gen:
	scripts/conformance.sh target/bpf_conformance ./tests/conformance ./tests/bpf-src/asm

clean:
	rm $(BPF_DIR)/*.txt

test: bpf-gen
	cargo test

.PHONY: bpf-gen test clean conformance-gen
