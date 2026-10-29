package main

import (
	"net/netip"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

var T = bpf.LPMTrie4[uint32]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = T.Put(netip.Prefix{}, 1)
	return bpf.XDPPass
}

func main() {}
