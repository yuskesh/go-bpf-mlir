package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.TCActContext) bpf.TCActAction {
	if ctx.Len() < 60 {
		return bpf.TCActShot
	}
	if ctx.Len() > 1500 {
		return bpf.TCActPipe
	}
	return bpf.TCActOK
}

func main() {}
