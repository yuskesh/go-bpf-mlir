package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The name is 1 to 15 characters (TCP_CA_NAME_MAX 16 minus the terminator — setsockopt TCP_CONGESTION copies at most 15). 16 characters stop.
var CC = bpf.TCPCongestionOps{Name: "gobpf_0123456789"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
