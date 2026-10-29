package main

import (
	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/frontend/testdata/slot_other_pkg/sub"
)

var S = bpf.ProgArray{MaxEntries: 4}

var _ = bpf.TailSlot(&S, 0, sub.F)

func main() {}
