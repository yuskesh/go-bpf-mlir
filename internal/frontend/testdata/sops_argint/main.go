package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// cong_avoid's acked (argument 2) is u32 — StructOpsArgInt's type argument must be uint32.
var (
	CC  = bpf.TCPCongestionOps{Name: "gobpf_x"}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {
	acked := bpf.StructOpsArgInt[uint64](ctx, 2)
	Out.AtomicAdd(0, acked)
}

func main() {}
