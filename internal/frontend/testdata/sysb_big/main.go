package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// TestAttrLimit: the map_create attr record is 81 bytes (the limit is 80 — the offset of excl_prog_hash on 7.1.8) — ebpf-compile stops.
type BigAttr struct {
	Bytes [81]byte `schema:"bytes"`
}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	st := bpf.SysBpf(ctx, bpf.SysBpfMapCreate, BigAttr{})
	return bpf.SyscallRet(int32(st))
}

func main() {}
