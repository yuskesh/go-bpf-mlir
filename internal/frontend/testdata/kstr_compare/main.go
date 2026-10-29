package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Comparing KernelStr fields (`p.Filename == p.Filename`).
type Binprm struct {
	_        bpf.Kernel    `kernel:"linux_binprm"`
	Filename bpf.KernelStr `kernel:"filename"`
}

type Ev struct {
	Name [32]byte `schema:"name" gobpf:"kernelstr"`
	St   int64    `schema:"st" gobpf:"kernelstr_status"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry security_bprm_check
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Binprm](ctx, 0); p != nil {
		if p.Filename == p.Filename {
			Out.AtomicAdd(0, 1)
		}
	}
}

func main() {}
