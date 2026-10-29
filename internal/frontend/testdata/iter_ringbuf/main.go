package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	A uint64 `schema:"a"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

// A ring buffer cannot be the target of a bpf_map_elem iterator (the kernel's bpf_iter_attach_map takes only array / hash).
//
//gobpf:iter bpf_map_elem Events
func f(ctx *bpf.IterContext) {
}

func main() {}
