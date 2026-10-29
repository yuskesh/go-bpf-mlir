package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: sockmap and sockhash, sk_skb Redirect (ingress), RedirectIf (egress), verdict only, ctx Len / LocalPort.

var (
	Socks = bpf.SockMap{MaxEntries: 2}
	Hash  = bpf.SockHash[uint64]{MaxEntries: 4}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

//gobpf:sk_skb Socks
func toPeer(ctx *bpf.SKSKBContext) bpf.SKAction {
	Out.Update(0, uint64(ctx.LocalPort()))
	return Socks.Redirect(ctx, 1, bpf.SKIngress)
}

//gobpf:sk_skb Hash
func viaHash(ctx *bpf.SKSKBContext) bpf.SKAction {
	return Hash.RedirectIf(ctx, ctx.Len() > 100, 7, bpf.SKEgress, bpf.SKPass)
}

func main() {}
