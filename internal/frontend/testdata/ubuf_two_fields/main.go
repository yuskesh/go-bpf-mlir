package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	A      [8]byte  `schema:"a" gobpf:"userbuf"`
	B      [12]byte `schema:"b" gobpf:"userbuf"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe bfix buf_write
func f(ctx *bpf.UprobeContext) {
	_, _, _ = Bufs.OutputBuf(Ev{}, bpf.UprobeBuf(ctx, 2), 4)
}

func main() {}
