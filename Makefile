GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_BUILD := GOOS=$(GOOS) GOARCH=$(GOARCH) go build
GO_BUILD_TARGET := siper

CLANG := clang
CFLAGS := -O2 -target bpf -g -c

MULTIARCH ?= $(shell gcc -print-multiarch 2>/dev/null)
ifeq ($(strip $(MULTIARCH)),)
	MULTIARCH := $(shell gcc -dumpmachine 2>/dev/null)
endif
ifneq ($(wildcard /usr/include/$(MULTIARCH)),)
	CFLAGS += -I/usr/include/$(MULTIARCH)
endif

BUILD_DIR := build

BPF_SOURCE_DIR := bpf
BPF_BUILD_DIR := $(BUILD_DIR)
BPF_SOURCE := $(wildcard $(BPF_SOURCE_DIR)/*.bpf.c)
BPF_OBJECTS := $(patsubst $(BPF_SOURCE_DIR)/%.bpf.c, $(BPF_BUILD_DIR)/%.o, $(BPF_SOURCE))

FORMATTER := scripts/formatter.sh

all: siper-go siper-bpf

siper-go:
	$(GO_BUILD) -o ./$(BUILD_DIR)/$(GO_BUILD_TARGET) ./cmd

siper-bpf: $(BPF_OBJECTS)

$(BPF_BUILD_DIR)/%.o: $(BPF_SOURCE_DIR)/%.bpf.c
	$(CLANG) $(CFLAGS) $< -o $@

clean:
	rm -f $(BPF_OBJECTS)
	rm -f $(BUILD_DIR)/*

format:
	$(FORMATTER)
