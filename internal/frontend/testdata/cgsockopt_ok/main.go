package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: cgroup_sockopt — reading Level, Optname and Optlen for set / get, SetOptlen, reading and writing the optval window; verdicts CgroupDeny / CgroupAllow.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func onSet(ctx *bpf.CgroupSetsockoptContext) bpf.CgroupAction {
	prio := ctx.Level() == 1 && ctx.Optname() == 12
	if w, ok := ctx.Check(0, 4); ok {
		Out.Update(0, uint64(w.LE32(0)))
		if prio {
			w.SetLE32(0, 5)
		}
	}
	if ctx.Optlen() > 8 {
		ctx.SetOptlen(-1)
	}
	if !prio {
		return bpf.CgroupDeny
	}
	return bpf.CgroupAllow
}

func onGet(ctx *bpf.CgroupGetsockoptContext) bpf.CgroupAction {
	Out.Update(1, uint64(ctx.Level())<<32|uint64(ctx.Optname()))
	if w, ok := ctx.Check(0, 1); ok {
		w.SetU8(0, 6)
	}
	if ctx.Optlen() > 4 {
		ctx.SetOptlen(4) // SetOptlen here is checked by generation and ebpf-compile only (the differential test measures only set's −1)
	}
	return bpf.CgroupAllow
}

func main() {}
