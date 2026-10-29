package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Passes the xdp context — GB000 (Go type).
type FrzAttr struct {
	MapFd uint32 `schema:"map_fd"`
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = bpf.SysBpf(ctx, bpf.SysBpfMapFreeze, FrzAttr{MapFd: 3})
	return bpf.XDPPass
}

func main() {}
