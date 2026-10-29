package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// An attach-dependent read (KprobeArg) inside a callee that takes the context — bpf-mlir refuses kprobe.arg in a callee (GB013).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func nfds(ctx *bpf.KprobeContext) uint32 {
	return bpf.KprobeArg[uint32](ctx, 2)
}

//gobpf:kprobe do_sys_poll
func onPoll(ctx *bpf.KprobeContext) {
	Out.Update(0, uint64(nfds(ctx)))
}

func main() {}
