package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Status int64      `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32      `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [8196]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 1 << 15}

//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 2), 4)
}

func main() {}
