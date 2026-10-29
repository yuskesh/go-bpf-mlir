package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A pointer in the middle of a field path (`f.Path.Dentry.Flags` — the pointer may be NULL) — GB005.
type File struct {
	_    bpf.Kernel `kernel:"file"`
	Path Path       `kernel:"f_path"`
}

type Path struct {
	_      bpf.Kernel `kernel:"path"`
	Dentry *Dentry    `kernel:"dentry"`
}

type Dentry struct {
	_     bpf.Kernel `kernel:"dentry"`
	Flags uint32     `kernel:"d_flags"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:fentry security_file_open
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[File](ctx, 0); p != nil {
		Out.Update(0, p.Path.Dentry.Flags)
	}
}

func main() {}
