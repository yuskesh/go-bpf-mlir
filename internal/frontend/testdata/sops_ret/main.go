package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// ssthresh's result type is uint32 (tcp_congestion_ops's u32 (*ssthresh)(struct sock *)).
var CC = bpf.TCPCongestionOps{Name: "gobpf_x"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint64 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
