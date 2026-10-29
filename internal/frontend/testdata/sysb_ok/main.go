package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case for SysBpf / SysClose — three cmds and SysClose, top-level statements.
type MkAttr struct {
	MapType    uint32 `schema:"map_type"`
	KeySize    uint32 `schema:"key_size"`
	ValueSize  uint32 `schema:"value_size"`
	MaxEntries uint32 `schema:"max_entries"`
}

type FrzAttr struct {
	MapFd uint32 `schema:"map_fd"`
}

type IDAttr struct {
	MapID     uint32 `schema:"map_id"`
	NextID    uint32 `schema:"next_id"`
	OpenFlags uint32 `schema:"open_flags"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	id := bpf.SyscallLoad[uint32](ctx, 0)
	fd := bpf.SysBpf(ctx, bpf.SysBpfMapCreate, MkAttr{MapType: 2, KeySize: 4, ValueSize: 8, MaxEntries: 3})
	fz := bpf.SysBpf(ctx, bpf.SysBpfMapFreeze, FrzAttr{MapFd: uint32(fd)})
	c := bpf.SysClose(ctx, int32(fd))
	_ = bpf.SysBpf(ctx, bpf.SysBpfMapGetFdByID, IDAttr{MapID: id})
	Out.Update(0, uint64(fd))
	Out.Update(1, uint64(fz))
	Out.Update(2, uint64(c))
	return bpf.SyscallRet(0)
}

func main() {}
