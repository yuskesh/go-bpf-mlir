package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Tasks = bpf.TaskStorage[uint64]{MaxEntries: 4}

func main() {}
