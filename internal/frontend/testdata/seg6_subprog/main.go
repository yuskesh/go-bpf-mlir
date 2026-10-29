package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The lwt_seg6local context cannot be passed to a subprogram (read it in the program body — pass integers).
func marked(ctx *bpf.Seg6LocalContext) uint32 {
	if ctx.Mark() == 17 {
		return 1
	}
	return 0
}

func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
	if marked(ctx) == 1 {
		return bpf.Seg6Drop
	}
	return bpf.Seg6OK
}

func main() {}
