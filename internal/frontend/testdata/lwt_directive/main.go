package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lwt takes no directive (the type determines the kind; the route is an argument of gobpf.AttachLWTRoute).
//
//gobpf:lwt_out
func onOut(ctx *bpf.LWTOutContext) bpf.LWTAction {
	return bpf.LWTOK
}

func main() {}
