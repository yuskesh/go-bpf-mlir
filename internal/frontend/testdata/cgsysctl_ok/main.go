package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: cgroup_sysctl — reading Write and FilePos, SetFilePos, SetNewValue (a string constant — the raw status); verdicts CgroupDeny / CgroupAllow.

var (
	Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 4}
)

func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
	mode := uint64(0)
	if v := Ctl.Lookup(0); v != nil {
		mode = *v
	}
	write := ctx.Write() != 0
	if write {
		Out.AtomicAdd(0, 1)
	}
	if !write {
		Out.AtomicAdd(1, 1)
	}
	if write && mode != 0 {
		st := ctx.SetNewValue("63\n")
		Out.Update(2, uint64(st))
	}
	if !write && mode == 3 {
		st := ctx.SetNewValue("63\n")
		Out.Update(3, uint64(st))
	}
	if ctx.FilePos() > 4096 { // FilePos / SetFilePos are checked by generation and ebpf-compile only (the differential test does not measure them)
		ctx.SetFilePos(0)
	}
	if write && mode == 2 {
		return bpf.CgroupDeny
	}
	return bpf.CgroupAllow
}

func main() {}
