package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SkbUnder's first argument must be the program's context parameter (bpf-mlir — the entry ctx).

var CG = bpf.CgroupArray{MaxEntries: 4}

func onSkb(ctx *bpf.TCIngressContext) bpf.TCAction {
	var other *bpf.TCEgressContext
	if CG.SkbUnder(other, 0) == 1 {
		return bpf.TCDrop
	}
	return bpf.TCPass
}

func main() {}
