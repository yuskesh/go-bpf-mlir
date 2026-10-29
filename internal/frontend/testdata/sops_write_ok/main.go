package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type TcpSock struct {
	_           bpf.Kernel `kernel:"tcp_sock"`
	SndCwnd     uint32     `kernel:"snd_cwnd"`
	SndSsthresh uint32     `kernel:"snd_ssthresh"`
}

var (
	CC  = bpf.TCPCongestionOps{Name: "gobpf_w"}
	Out = bpf.Array[uint32, uint32]{MaxEntries: 2}
)

//gobpf:struct_ops CC init
func ini(ctx *bpf.StructOpsContext) {
	if sk := bpf.StructOpsArg[TcpSock](ctx, 0); sk != nil {
		Out.Update(0, sk.SndCwnd)
		sk.SndSsthresh = 64
	}
}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 {
	r := uint32(2)
	if sk := bpf.StructOpsArg[TcpSock](ctx, 0); sk != nil {
		r = sk.SndCwnd >> 1
	}
	return r
}

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {
	ack := bpf.StructOpsArgInt[uint32](ctx, 1)
	acked := bpf.StructOpsArgInt[uint32](ctx, 2)
	Out.Update(1, ack)
	if sk := bpf.StructOpsArg[TcpSock](ctx, 0); sk != nil {
		sk.SndCwnd = sk.SndCwnd + acked
	}
}

func main() {}
