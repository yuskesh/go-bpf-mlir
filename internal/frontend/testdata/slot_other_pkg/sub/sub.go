package sub

import "github.com/yuskesh/go-bpf-mlir/bpf"

func F(ctx *bpf.XDPContext) bpf.XDPAction { return bpf.XDPPass }
