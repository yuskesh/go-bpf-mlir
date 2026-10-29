package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	C = bpf.CPUMap{MaxEntries: 1}
	D = bpf.DevMapHash{MaxEntries: 8}
	X = bpf.XSKMap{MaxEntries: 4}
	K = bpf.Array[uint32, uint32]{MaxEntries: 1}
)

// Positive case: Redirect and RedirectIf for the three kinds.

func toCPU(ctx *bpf.XDPContext) bpf.XDPAction {
	return C.Redirect(ctx, 0, bpf.XDPDrop)
}

func toDev(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if p := K.Lookup(0); p != nil {
		k = *p
	}
	return D.RedirectIf(ctx, k != 0, k, bpf.XDPPass, bpf.XDPAborted)
}

func toXSK(ctx *bpf.XDPContext) bpf.XDPAction {
	return X.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
