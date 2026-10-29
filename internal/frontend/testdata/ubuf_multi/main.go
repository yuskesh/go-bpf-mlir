package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [20]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

// A user buffer in a uprobe_multi program is out of scope (integer arguments only).
//
//gobpf:uprobe_multi umfix um_add um_mul
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 1), 4)
}

func main() {}
