package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// lwt_seg6local takes no directive (the type determines the kind; the route is an argument of gobpf.AttachSeg6Local).
//
//gobpf:lwt_seg6local
func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
	return bpf.Seg6OK
}

func main() {}
