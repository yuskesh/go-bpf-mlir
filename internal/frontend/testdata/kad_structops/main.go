package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr in a struct_ops program (not one of bpf-mlir's six kptr.addr kinds) — GB027.
type TcpSock struct {
	_       bpf.Kernel `kernel:"tcp_sock"`
	SndCwnd uint32     `kernel:"snd_cwnd"`
}

var (
	CC  = bpf.TCPCongestionOps{Name: "gobpf_kad"}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

//gobpf:struct_ops CC init
func ini(ctx *bpf.StructOpsContext) {
	if sk := bpf.StructOpsArg[TcpSock](ctx, 0); sk != nil {
		Out.Update(0, bpf.KernelAddr(sk))
	}
}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
