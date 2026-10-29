package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 32}

// Positive case: reading helpers (keyLong / keyShort) from xdp and tc, a writing helper (swapMAC) from xdp only.
func keyLong(w bpf.Window) uint32 {
	et := w.BE16(12)
	k := uint32(3)
	if et == 0x0800 {
		k = uint32(w.U8(23)) & 7
	}
	return k
}

func keyShort(w bpf.Window) uint32 {
	k := uint32(4)
	if w.BE16(12) == 0x0800 {
		k = 5
	}
	return k
}

func swapMAC(w bpf.Window) uint32 {
	a := w.BE16(0)
	w.SetBE16(0, w.BE16(6))
	w.SetBE16(6, a)
	return uint32(a)
}

func countXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(6)
	if w, ok := ctx.Check(0, 24); ok {
		k = keyLong(w)
		_ = swapMAC(w)
	} else {
		if w2, ok2 := ctx.Check(0, 14); ok2 {
			k = keyShort(w2)
		}
	}
	if k >= 8 {
		k = 7
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func countIngress(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := uint32(6)
	if w, ok := ctx.Check(0, 24); ok {
		k = keyLong(w)
	}
	if k >= 8 {
		k = 7
	}
	Counts.AtomicAdd(8+k, 1)
	return bpf.TCPass
}

func main() {}
