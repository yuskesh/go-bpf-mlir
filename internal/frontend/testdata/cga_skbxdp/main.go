package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SkbUnder is only in the body of a tc program (bpf-mlir's ebpf.skb.under_cgroup takes the sched_cls entry ctx — xdp has no skb socket).

var CG = bpf.CgroupArray{MaxEntries: 4}

func onSkb(ctx *bpf.TCIngressContext) bpf.TCAction { return bpf.TCPass }

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	var tc *bpf.TCIngressContext
	if CG.SkbUnder(tc, 0) == 1 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

func main() {}
