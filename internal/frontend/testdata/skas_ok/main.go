package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case for Assign — SockMap and SockHash, four flags values (0, replace, no_reuseport, both), inside an if arm.
var Socks = bpf.SockMap{MaxEntries: 4}

var Hash = bpf.SockHash[uint32]{MaxEntries: 4}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	st, found := Socks.Assign(ctx, 0, 0)
	if found {
		Out.Update(0, uint64(st))
	}
	if ctx.LocalPort() == 7 {
		_, _ = Socks.Assign(ctx, 1, bpf.SkAssignReplace)
	}
	st2, _ := Hash.Assign(ctx, 10, bpf.SkAssignNoReuseport)
	Out.Update(1, uint64(st2))
	_, f3 := Socks.Assign(ctx, 2, bpf.SkAssignReplace|bpf.SkAssignNoReuseport)
	if f3 {
		Out.Update(2, 1)
	}
	return bpf.SKPass
}

func main() {}
