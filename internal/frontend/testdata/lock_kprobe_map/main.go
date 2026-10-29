package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pair struct {
	Lock bpf.SpinLock `schema:"lock"`
	A    uint32       `schema:"a"`
	B    uint32       `schema:"b"`
}

type Win struct {
	T bpf.Timer `schema:"t"`
	N uint64    `schema:"n"`
}

var Pairs = bpf.Array[uint32, Pair]{MaxEntries: 1}
var Wins = bpf.Array[uint32, Win]{MaxEntries: 1}

//gobpf:kprobe do_sys_poll
func onPoll(ctx *bpf.KprobeContext) {
	if p := Pairs.Lookup(0); p != nil {
		p.A++
	}
}

func main() {}
