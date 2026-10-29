package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [20]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

// Argument 3 of buf_write is an int, not a pointer.
//
//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 3), 4)
}

func main() {}
