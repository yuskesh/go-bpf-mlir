package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// OutputKernelStr inside a loop — GB018.
type Binprm struct {
	_        bpf.Kernel    `kernel:"linux_binprm"`
	Filename bpf.KernelStr `kernel:"filename"`
}

type Ev struct {
	Name [32]byte `schema:"name" gobpf:"kernelstr"`
	St   int64    `schema:"st" gobpf:"kernelstr_status"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:fentry security_bprm_check
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Binprm](ctx, 0); p != nil {
		for i := uint32(0); i < 2; i++ {
			_, _ = Events.OutputKernelStr(Ev{}, p.Filename)
		}
	}
}

func main() {}
