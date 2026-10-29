package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Every byte is a named field (no `_` padding), so record.make covers the record.
type Ev struct {
	Ctx    uint64   `schema:"ctx"`
	Status int64    `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32    `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [16]byte `schema:"buf" gobpf:"userbuf"`
	Pad    uint32   `schema:"pad"`
}

var Bufs = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe bfix buf_write
func onWrite(ctx *bpf.UprobeContext) {
	n := int64(bpf.UprobeArg[int32](ctx, 3))
	st, cnt, ok := Bufs.OutputBuf(Ev{Ctx: uint64(bpf.UprobeArg[uintptr](ctx, 1))}, bpf.UprobeBuf(ctx, 2), n)
	Out.Update(0, uint64(st))
	Out.Update(1, uint64(cnt))
	if ok {
		Out.AtomicAdd(2, 1)
	}
}

//gobpf:uprobe bfix buf_argv
func onArgv(ctx *bpf.UprobeContext) {
	Out.Update(3, uint64(bpf.UprobeArg[int32](ctx, 2)))
}

func main() {}
