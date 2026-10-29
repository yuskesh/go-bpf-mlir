package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Tasks = bpf.TaskStorage[uint64]{}

func main() {
	_ = Tasks.Get(nil, bpf.Create)
}
