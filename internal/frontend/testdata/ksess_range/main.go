package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// kprobe_session returns only 0 / 1 (bpf-mlir's verdict `done|int:0..1`).
//
//gobpf:kprobe_session bpf_fentry_test1
func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
	return 2
}

func main() {}
