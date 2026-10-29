package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The kprobe_session directive names only one function (a list is kprobe_multi).
//
//gobpf:kprobe_session bpf_fentry_test1 bpf_fentry_test2
func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
	return bpf.KprobeSessionRun
}

func main() {}
