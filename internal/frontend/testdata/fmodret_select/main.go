package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// In the final `if c { return A }; return B`, both A and B are evaluated before the select — expressions with side effects or traps (map calls, division) are not allowed.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fmod_ret bpf_modify_return_test nargs=2
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	a := bpf.FmodRetArgInt[int32](ctx, 0)
	if a > 0 {
		return bpf.FmodRet(100 / a)
	}
	return 0
}

func main() {}
