package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Seq uint64   `schema:"seq"`
	Cnt int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf [20]byte `schema:"buf" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 2), 4)
}

func main() {}
