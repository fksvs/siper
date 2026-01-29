GO_BUILD := GOOS=$(GOOS) GOARCH=$(GOARCH) go build

CLANG := clang
CFLAGS := -O2 -target bpf -g -c

BUILD_DIR := build

BPF_SOURCE_DIR := bpf
BPF_BUILD_DIR := $(BUILD_DIR)
BPF_SOURCE := $(wildcard $(BPF_SOURCE_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst $(BPF_SOURCE_DIR)/%.bpf.c, $(BPF_BUILD_DIR)/%.o, $(BPF_SOURCE))

FORMATTER := scripts/formatter.sh

all: siper-go siper-bpf

siper-go:
	cd cmd && $(GO_BUILD) -o ../$(BUILD_DIR)/main .

siper-bpf: $(BPF_OBJECTS)

$(BPF_BUILD_DIR)/%.o: $(BPF_SOURCE_DIR)/%.bpf.c
	$(CLANG) $(CFLAGS) $< -o $@

clean:
	rm -f $(BPF_OBJECTS)
	rm -f $(BUILD_DIR)/*

format:
	$(FORMATTER)
