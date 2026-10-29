package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case for OutputKernelStr — linux_binprm's filename (char *) into [32]byte, the status into int64.
type Binprm struct {
	_        bpf.Kernel    `kernel:"linux_binprm"`
	Filename bpf.KernelStr `kernel:"filename"`
}

type Ev struct {
	Tag  uint32   `schema:"tag"`
	Name [32]byte `schema:"name" gobpf:"kernelstr"`
	_    [4]byte
	St   int64 `schema:"st" gobpf:"kernelstr_status"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 2}

//gobpf:fentry security_bprm_check
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Binprm](ctx, 0); p != nil {
		st, ok := Events.OutputKernelStr(Ev{Tag: 7}, p.Filename)
		Out.Update(0, uint64(st))
		if ok {
			Out.AtomicAdd(1, 1)
		}
	}
}

func main() {}
