BPF_DIR := tests/bpf-src
BPF_SOURCE := $(BPF_DIR)/%.txt

$(BPF_SOURCE): $(BPF_DIR)/%.c
	clang -target bpf -mcpu=v3 -Wall -O1 -c "$<" -o - | llvm-objdump -r -S - > "$@"

bpf-gen: $(addsuffix .txt, $(basename $(wildcard $(BPF_DIR)/*.c)))

conformance-gen:
	../scripts/conformance.sh tests/bpf_conformance ./tests/conformance ./tests/bpf-src/asm

bpf-samples:
	git clone https://github.com/yesh0/ebpf-samples.git tests/bpf-samples

clean:
	rm $(BPF_DIR)/*.txt

.PHONY: bpf-gen clean conformance-gen
