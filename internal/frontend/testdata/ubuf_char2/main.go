package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [20]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

// Argument 1 of buf_argv is a char ** (a pointer to pointers), not a single-level pointer.
//
//gobpf:uprobe bfix buf_argv
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 1), 8)
}

func main() {}
