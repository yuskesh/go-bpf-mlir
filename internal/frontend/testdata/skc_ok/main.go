package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 16}

// Positive case: six context reads, write methods, verdicts (conditional ones too), a cgroup_skb packet window.

func sf(ctx *bpf.SocketFilterContext) bpf.SocketFilterAction {
	if ctx.Len() > 64 {
		return bpf.SocketDrop
	}
	return bpf.SocketKeep
}

func ing(ctx *bpf.CgroupSKBIngressContext) bpf.CgroupAction {
	Out.AtomicAdd(0, uint64(ctx.Len()))
	if w, ok := ctx.Check(0, 20); ok {
		Out.Update(1, uint64(w.U8(9)))
	}
	return bpf.CgroupAllow
}

func egr(ctx *bpf.CgroupSKBEgressContext) bpf.CgroupAction {
	return bpf.CgroupAllow
}

//gobpf:cgroup_sock sock_create
func create(ctx *bpf.CgroupSockContext) bpf.CgroupAction {
	Out.Update(2, uint64(ctx.Family())<<32|uint64(ctx.Type())<<16|uint64(ctx.Protocol()))
	ctx.SetMark(0x5a)
	return bpf.CgroupAllow
}

//gobpf:cgroup_sock post_bind4
func bound(ctx *bpf.CgroupSockContext) bpf.CgroupAction {
	Out.Update(3, uint64(ctx.SrcIP4())<<32|uint64(ctx.SrcPort()))
	return bpf.CgroupAllow
}

//gobpf:cgroup_sock_addr connect4
func conn(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	p := ctx.UserPort()
	if p == 0x621e {
		ctx.SetUserPort(0xb822)
		ctx.SetUserIP4(ctx.UserIP4())
	}
	Out.Update(4, uint64(ctx.Type()))
	if p == 0x611e {
		return bpf.CgroupDeny
	}
	return bpf.CgroupAllow
}

//gobpf:cgroup_sock_addr getsockname4
func gsn(ctx *bpf.SockAddrContext) bpf.CgroupAction {
	Out.Update(5, uint64(ctx.Family()))
	return bpf.CgroupAllow
}

func ops(ctx *bpf.SockOpsContext) bpf.CgroupAction {
	Out.Update(6, uint64(ctx.Op())<<32|uint64(ctx.LocalPort()))
	Out.Update(7, uint64(ctx.RemotePort())|uint64(ctx.Family())<<32)
	ctx.SetReply(0)
	return bpf.CgroupAllow
}

func main() {}
