package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lwt_seg6local verdicts are bpf.Seg6Action only (lwt's LWTAction is also a type error).
func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
	return bpf.LWTOK
}

func main() {}
