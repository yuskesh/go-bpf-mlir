package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Two programs for the same member (one program per member).
var CC = bpf.TCPCongestionOps{Name: "gobpf_x"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC ssthresh
func ss2(ctx *bpf.StructOpsContext) uint32 { return 3 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
