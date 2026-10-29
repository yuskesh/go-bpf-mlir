package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A struct_ops write through an embedded kernel struct (`sk.Conn.F = x` — bpf-mlir's kfield.store takes one segment) — GB027.
type TcpSock struct {
	_       bpf.Kernel   `kernel:"tcp_sock"`
	SndCwnd uint32       `kernel:"snd_cwnd"`
	Conn    InetConnSock `kernel:"inet_conn"`
}

type InetConnSock struct {
	_       bpf.Kernel `kernel:"inet_connection_sock"`
	Retrans uint8      `kernel:"icsk_retransmits"`
}

var CC = bpf.TCPCongestionOps{Name: "gobpf_kp"}

//gobpf:struct_ops CC init
func ini(ctx *bpf.StructOpsContext) {
	if sk := bpf.StructOpsArg[TcpSock](ctx, 0); sk != nil {
		sk.Conn.Retrans = 0
	}
}

//gobpf:struct_ops CC ssthresh
func ss(ctx *bpf.StructOpsContext) uint32 { return 2 }

//gobpf:struct_ops CC undo_cwnd
func undo(ctx *bpf.StructOpsContext) uint32 { return 10 }

//gobpf:struct_ops CC cong_avoid
func avoid(ctx *bpf.StructOpsContext) {}

func main() {}
