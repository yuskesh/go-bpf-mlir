package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Ptr    uint64   `schema:"ptr"`
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [20]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

// One argument has one kind in the schema params: argument 2 cannot be both a raw pointer and a user buffer.
//
//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	p := uint64(bpf.UprobeArg[uintptr](ctx, 2))
	_, _, _ = Bufs.OutputBuf(Ev{Ptr: p}, bpf.UprobeBuf(ctx, 2), 4)
}

func main() {}
