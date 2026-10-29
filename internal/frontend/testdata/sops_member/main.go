package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A member outside the table (cong_control has a different signature on 6.6).
var CC = bpf.TCPCongestionOps{Name: "gobpf_x"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

//gobpf:struct_ops CC cong_control
func ctl(ctx *bpf.StructOpsContext) {}

func main() {}
