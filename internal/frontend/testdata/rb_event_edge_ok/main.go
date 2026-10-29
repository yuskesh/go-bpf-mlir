package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Edge is 4080 bytes — the largest that fits in a 4096 ring (MaxEntries - 16).
type Edge struct {
	Seq uint64     `schema:"seq"`
	Buf [4072]byte `schema:"buf"`
}

// Big is 65520 bytes — the largest that fits in a 65536 ring (N - 16 — the larger boundary; 65520 + 8 = 65528 <= 65535).
type Big struct {
	Seq uint64      `schema:"seq"`
	Buf [65512]byte `schema:"buf"`
}

var Edges = bpf.RingBuf[Edge]{MaxEntries: 4096}

var Bigs = bpf.RingBuf[Big]{MaxEntries: 65536}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Edges.Output(Edge{Seq: 1})
	_ = Bigs.Output(Big{Seq: 2})
	return bpf.XDPPass
}

func main() {}
