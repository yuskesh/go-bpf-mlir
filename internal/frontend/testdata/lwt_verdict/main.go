package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lwt verdicts are bpf.LWTAction only (constants of other kinds are a type error).
func onOut(ctx *bpf.LWTOutContext) bpf.LWTAction {
	return bpf.XDPPass
}

func main() {}
