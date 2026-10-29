package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// At most one struct_ops map per package (cilium may mix up programs of two maps of the same type by member name).
var (
	CC  = bpf.TCPCongestionOps{Name: "gobpf_a"}
	CC2 = bpf.TCPCongestionOps{Name: "gobpf_b"}
)

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
