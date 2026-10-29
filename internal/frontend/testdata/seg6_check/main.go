package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lwt_seg6local offers no packet window (only five ctx fields and the verdict — see limits).
func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
	if _, ok := ctx.Check(40, 8); ok {
		return bpf.Seg6Drop
	}
	return bpf.Seg6OK
}

func main() {}
