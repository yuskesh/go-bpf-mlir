package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A write at an index outside the optval window stops (GB014 — the window is Check's n bytes).
func onGet(ctx *bpf.CgroupGetsockoptContext) bpf.CgroupAction {
	if w, ok := ctx.Check(0, 4); ok {
		w.SetLE32(2, 6)
	}
	return bpf.CgroupAllow
}

func main() {}
