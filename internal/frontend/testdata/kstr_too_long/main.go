package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The tag kernelstr field is 65 bytes (> 64) — GB016.
type Binprm struct {
	_        bpf.Kernel    `kernel:"linux_binprm"`
	Filename bpf.KernelStr `kernel:"filename"`
}

type Ev struct {
	Name [65]byte `schema:"name" gobpf:"kernelstr"`
	_    [7]byte
	St   int64 `schema:"st" gobpf:"kernelstr_status"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:fentry security_bprm_check
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Binprm](ctx, 0); p != nil {
		_, _ = Events.OutputKernelStr(Ev{}, p.Filename)
	}
}

func main() {}
