package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

type File struct {
	_     bpf.Kernel `kernel:"file"`
	Flags uint32     `kernel:"f_flags"`
}

// Positive case: lsm and lsm.s, reading LSMArg structs and fields, LSMArgInt widths and prefix (earlier arguments unread), LSMAllow / LSMDeny constants and conditional returns.

//gobpf:lsm socket_create
func create(ctx *bpf.LSMContext) bpf.LSMRet {
	fam := bpf.LSMArgInt[int32](ctx, 0)
	kern := bpf.LSMArgInt[int32](ctx, 3)
	Out.Update(0, uint64(fam)+uint64(kern))
	if fam == 44 && kern == 0 {
		return bpf.LSMDeny(1)
	}
	return bpf.LSMAllow
}

//gobpf:lsm_s socket_create
func createS(ctx *bpf.LSMSleepableContext) bpf.LSMRet {
	typ := bpf.LSMArgInt[int32](ctx, 1)
	Out.Update(1, uint64(typ))
	return bpf.LSMDeny(13)
}

//gobpf:lsm file_open
func open(ctx *bpf.LSMContext) bpf.LSMRet {
	if p := bpf.LSMArg[File](ctx, 0); p != nil {
		Out.Update(2, uint64(p.Flags))
	}
	return bpf.LSMAllow
}

//gobpf:lsm task_alloc
func alloc(ctx *bpf.LSMContext) bpf.LSMRet {
	flags := bpf.LSMArgInt[uint64](ctx, 1)
	Out.Update(3, flags)
	return bpf.LSMRet(-4095)
}

func main() {}
