package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: fsession — IsReturn, Cookie, SetCookie, filtering on the test's tgid.

var (
	Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 3}
)

//gobpf:fsession bpf_fentry_test1
func onSess(ctx *bpf.FsessionContext) {
	mine := false
	if v := Ctl.Lookup(0); v != nil {
		mine = *v == bpf.CurrentPidTgid()>>32
	}
	if mine {
		if ctx.IsReturn() {
			Out.AtomicAdd(1, 1)
			Out.AtomicAdd(2, ctx.Cookie())
		} else {
			Out.AtomicAdd(0, 1)
			ctx.SetCookie(0xE231)
		}
	}
}

func main() {}
