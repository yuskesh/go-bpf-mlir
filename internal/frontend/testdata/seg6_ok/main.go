package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: lwt_seg6local — reading five ctx fields and writing mark / priority, verdicts Seg6Drop / Seg6OK.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 3}

func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
	Out.Update(0, uint64(ctx.Len())+uint64(ctx.Protocol()))
	Out.Update(1, uint64(ctx.Ifindex()))
	if ctx.Mark() == 17 {
		ctx.SetMark(42)
		ctx.SetPriority(ctx.Priority() + 1)
	}
	if ctx.Len() > 1000 {
		return bpf.Seg6Drop
	}
	return bpf.Seg6OK
}

func main() {}
