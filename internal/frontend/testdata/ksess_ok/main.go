package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: kprobe_session — session ops and constant return values (a select from the final if).

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe_session bpf_fentry_test1
func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
	ret := ctx.IsReturn()
	if ret {
		Out.Update(0, ctx.Cookie())
	} else {
		ctx.SetCookie(7)
	}
	if !ret {
		return bpf.KprobeSessionSkipReturn
	}
	return bpf.KprobeSessionRun
}

func main() {}
