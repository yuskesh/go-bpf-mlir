package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// kprobe_session returns constants only (computed values are fmod_ret only — the existing constant path).

var Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe_session bpf_fentry_test1
func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
	m := bpf.KprobeSessionRet(0)
	if v := Ctl.Lookup(0); v != nil {
		m = bpf.KprobeSessionRet(*v & 1)
	}
	return m
}

func main() {}
