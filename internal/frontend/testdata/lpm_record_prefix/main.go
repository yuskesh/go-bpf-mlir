package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type gobpf_lpm_key4 struct {
	A uint32 `schema:"a"`
}

var H = bpf.Hash[uint32, gobpf_lpm_key4]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
