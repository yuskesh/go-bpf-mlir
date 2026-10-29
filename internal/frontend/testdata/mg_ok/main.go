package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: sk_msg MsgRedirect (egress) and six ctx fields, sock_ops Insert (sockmap, exist).

var (
	Socks = bpf.SockMap{MaxEntries: 4}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 8}
)

//gobpf:sk_msg Socks
func toPeer(ctx *bpf.SKMsgContext) bpf.SKAction {
	Out.Update(0, uint64(ctx.Size()))
	Out.Update(1, uint64(ctx.Family()))
	Out.Update(2, uint64(ctx.RemoteIP4()))
	Out.Update(3, uint64(ctx.LocalIP4()))
	Out.Update(4, uint64(ctx.RemotePort()))
	Out.Update(5, uint64(ctx.LocalPort()))
	return Socks.MsgRedirect(ctx, 1, bpf.SKEgress)
}

func ins(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	if ctx.Op() == 5 {
		st := Socks.Insert(ctx, 2, bpf.SockExist)
		Out.Update(6, uint64(st))
	}
	return bpf.CgroupAllow
}

func main() {}
