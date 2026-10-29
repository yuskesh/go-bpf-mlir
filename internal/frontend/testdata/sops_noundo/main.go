package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A required tcp_congestion_ops member (ssthresh, undo_cwnd, cong_avoid) is missing — stops before the kernel's tcp_validate EINVAL.
var CC = bpf.TCPCongestionOps{Name: "gobpf_x"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
