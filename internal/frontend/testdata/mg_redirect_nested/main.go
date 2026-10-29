package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

//gobpf:sk_msg Socks
func f(ctx *bpf.SKMsgContext) bpf.SKAction {
	if ctx.Size() == 5 {
		return bpf.SKDrop
	}
	return Socks.MsgRedirectIf(ctx, ctx.Size() == 7, 1, bpf.SKIngress, bpf.SKPass)
}

func main() {}
