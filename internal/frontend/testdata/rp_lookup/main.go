package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// On the eBPF side reuseport_sockarray has only Select — there is no Lookup (the kernel verifier also refuses lookup / update).

var Socks = bpf.ReuseportSockArray{MaxEntries: 2}

func onSelect(ctx *bpf.SkReuseportContext) bpf.SKAction {
	if v := Socks.Lookup(0); v != nil {
		return bpf.SKDrop
	}
	return bpf.SKPass
}

func main() {}
