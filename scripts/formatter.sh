#!/bin/bash

if ! command -v clang-format 2>&1 >/dev/null
then
        echo "clang-format not installed."
        exit 1
fi

if ! command -v go 2>&1 >/dev/null
then
        echo "Go not installed."
        exit 1
fi

GO_PROJECT_DIR="./"
GO_FILES=$(find "$GO_PROJECT_DIR" -type f -name "*.go")

CLANG_FORMAT_FILE="./configs/clang-format"
BPF_TARGET_DIR="./bpf/"
C_FILES=$(find "$BPF_TARGET_DIR" -type f -name "*.c" -o -name "*.h")

for FILE in $C_FILES; do
        echo "formatting C file: $FILE"
        clang-format -i --style=file:$CLANG_FORMAT_FILE $FILE
done

for FILE in $GO_FILES; do
        echo "formatting Go file: $FILE"
        go fmt "$FILE"
done

echo "formatting completed."

