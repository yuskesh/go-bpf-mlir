package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Passes the xdp context — GB000 (Go type).
var Socks = bpf.SockMap{MaxEntries: 4}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	_, _ = Socks.Assign(ctx, 0, 0)
	return bpf.XDPPass
}

func main() {}
