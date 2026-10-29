package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A variable key for (W) across functions — the caller reads R[k].N and the callee writes its argument to R[k].N (k is the same variable's value in both).
// The frontend cannot show the keys differ (not constants), so GB028 (fail closed). bpf-mlir's rmwprobe does not compare SSA keys across functions.
type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func writeK(k uint32, v uint64) bool {
	ok := false
	if p := R.Lookup(k & 3); p != nil {
		p.N = v
		ok = true
	}
	return ok
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.U8(0)) & 3
	}
	x := uint64(0)
	if p := R.Lookup(k); p != nil {
		x = p.N
	}
	_ = writeK(k, x+1)
	return bpf.XDPPass
}

func main() {}
