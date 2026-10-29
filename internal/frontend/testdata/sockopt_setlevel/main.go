package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Writes to level / optname are not offered (a bpf-mlir limit) — there is no SetLevel.
func onSet(ctx *bpf.CgroupSetsockoptContext) bpf.CgroupAction {
	ctx.SetLevel(6)
	return bpf.CgroupAllow
}

func main() {}
