package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.KernelAddr in a lsm program (not one of bpf-mlir's six kptr.addr kinds) — GB027.
type File struct {
	_     bpf.Kernel `kernel:"file"`
	Flags uint32     `kernel:"f_flags"`
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm file_open
func open(ctx *bpf.LSMContext) bpf.LSMRet {
	if p := bpf.LSMArg[File](ctx, 0); p != nil {
		Out.Update(0, bpf.KernelAddr(p))
	}
	return bpf.LSMAllow
}

func main() {}
