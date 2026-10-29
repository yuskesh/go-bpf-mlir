package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func mix(x, i uint32) uint32 {
	x = x*31 + i
	x ^= x >> 3
	x = x*17 + 7
	x ^= x << 5
	x = x*13 + i
	x ^= x >> 7
	x = x*11 + 3
	x ^= x << 2
	x = x*29 + i
	x ^= x >> 11
	x = x*23 + 5
	x ^= x << 9
	x = x*19 + i
	x ^= x >> 13
	x = x*7 + 1
	x ^= x << 3
	x = x*31 + i
	x ^= x >> 3
	x = x*17 + 7
	x ^= x << 5
	x = x*13 + i
	x ^= x >> 7
	x = x*11 + 3
	x ^= x << 2
	x = x*29 + i
	x ^= x >> 11
	x = x*23 + 5
	x ^= x << 9
	x = x*19 + i
	x ^= x >> 13
	x = x*7 + 1
	x ^= x << 3
	return x
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	var x uint32
	if p := Out.Lookup(3); p != nil {
		x = uint32(*p)
	}
	for i := uint32(0); i < 64; i++ {
		x = mix(x, i)
	}
	Out.Update(2, uint64(x))
	return bpf.XDPPass
}

func main() {}
