package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// StructOpsArg may be NULL — a write outside a nil check stops.
type TcpSock struct {
	_       bpf.Kernel `kernel:"tcp_sock"`
	SndCwnd uint32     `kernel:"snd_cwnd"`
}

var CC = bpf.TCPCongestionOps{Name: "gobpf_x"}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {
	bpf.StructOpsArg[TcpSock](ctx, 0).SndCwnd = 5
}

func main() {}
