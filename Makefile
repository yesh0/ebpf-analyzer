BPF_DIR := tests/bpf-src
BPF_SOURCE := $(BPF_DIR)/%.txt

$(BPF_SOURCE): $(BPF_DIR)/%.c
	clang -target bpf -Wall -O1 -c "$<" -o - | llvm-objdump -S - > "$@"

bpf-gen: $(addsuffix .txt, $(basename $(wildcard $(BPF_DIR)/*.c)))

clean:
	rm $(BPF_DIR)/*.txt

test: bpf-gen
	cargo test

.PHONY: test clean
