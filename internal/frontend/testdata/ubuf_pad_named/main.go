package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The control of ubuf_pad_stack: the same 8 KiB event with the padding named, so record.make covers every byte and the event is stored
// straight into the reservation.
type BigEv struct {
	Ctx    uint64     `schema:"ctx"`
	Len    int64      `schema:"len"`
	Status int64      `schema:"status" gobpf:"userbuf_status"`
	Cnt    int32      `schema:"cnt" gobpf:"userbuf_len"`
	Buf    [8192]byte `schema:"buf" gobpf:"userbuf"`
	Pad    uint32     `schema:"pad"`
}

var Big = bpf.RingBuf[BigEv]{MaxEntries: 1 << 17}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:uprobe bfix buf_write
func onWrite(ctx *bpf.UprobeContext) {
	n := int64(bpf.UprobeArg[int32](ctx, 3))
	_, _, ok := Big.OutputBuf(BigEv{Len: n}, bpf.UprobeBuf(ctx, 2), n)
	if !ok {
		Out.AtomicAdd(0, 1)
	}
}

func main() {}
