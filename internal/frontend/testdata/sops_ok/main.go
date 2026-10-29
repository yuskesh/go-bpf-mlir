package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	CC  = bpf.TCPCongestionOps{Name: "gobpf_ok"}
	Out = bpf.Array[uint32, uint32]{MaxEntries: 2}
)

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 {
	v := uint32(2)
	if p := Out.Lookup(0); p != nil {
		v = *p
	}
	if v > 100 {
		return 100
	}
	return v
}

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) { Out.AtomicAdd(1, 1) }

func main() {}
