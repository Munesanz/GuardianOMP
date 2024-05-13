#!/bin/bash

# Ensure a binary path is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <binary_path>"
    exit 1
fi

binary_path="$1"

# Check if the binary exists
if [ ! -f "$binary_path" ]; then
    echo "Error: Binary file does not exist."
    exit 1
fi

# Use objdump to list symbols and grep for .data and .bss sections
objdump -t $binary_path | grep ' g ' | awk '
$4 == ".data" || $4 == ".bss" {
    print $1, $5  # Address, Size, and Variable Name
}' > object_file.txt

echo "Done"
