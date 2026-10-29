package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The tag kernelstr field is not [N]byte — GB016.
type Binprm struct {
	_        bpf.Kernel    `kernel:"linux_binprm"`
	Filename bpf.KernelStr `kernel:"filename"`
}

type Ev struct {
	Name [8]uint32 `schema:"name" gobpf:"kernelstr"`
	St   int64     `schema:"st" gobpf:"kernelstr_status"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:fentry security_bprm_check
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Binprm](ctx, 0); p != nil {
		_, _ = Events.OutputKernelStr(Ev{}, p.Filename)
	}
}

func main() {}
