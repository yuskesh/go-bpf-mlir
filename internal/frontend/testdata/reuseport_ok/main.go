package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: sk_reuseport — reading five fields, ReuseportSockArray.Select (raw status), verdicts SKDrop / SKPass.

var (
	Socks = bpf.ReuseportSockArray{MaxEntries: 2}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

func onSelect(ctx *bpf.SkReuseportContext) bpf.SKAction {
	Out.Update(0, uint64(ctx.Len())<<32|uint64(ctx.EthProtocol()))
	st := Socks.Select(ctx, ctx.Hash()&1)
	Out.Update(1, uint64(st))
	if ctx.IPProtocol() != 17 || ctx.BindInany() != 0 {
		return bpf.SKDrop
	}
	return bpf.SKPass
}

func main() {}
