package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: fmod_ret — reading integer arguments and a computed FmodRet return value (a select from the final if).

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fmod_ret bpf_modify_return_test nargs=2
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	a := bpf.FmodRetArgInt[int32](ctx, 0)
	Out.Update(0, uint64(a))
	if a > 0 {
		return bpf.FmodRet(a*2 + 1)
	}
	return -1
}

func main() {}
