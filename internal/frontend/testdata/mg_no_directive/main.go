package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

func f(ctx *bpf.SKMsgContext) bpf.SKAction {
	return Socks.MsgRedirect(ctx, 0, bpf.SKIngress)
}

func main() {}
