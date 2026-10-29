package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A kernel field path of 4 segments (bpf-mlir reads 1 to 3) — GB027.
type A struct {
	_ bpf.Kernel `kernel:"a"`
	B B          `kernel:"b"`
}

type B struct {
	_ bpf.Kernel `kernel:"b"`
	C C          `kernel:"c"`
}

type C struct {
	_ bpf.Kernel `kernel:"c"`
	D D          `kernel:"d"`
}

type D struct {
	_ bpf.Kernel `kernel:"d"`
	X uint32     `kernel:"x"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[A](ctx, 0); p != nil {
		Out.Update(0, p.B.C.D.X)
	}
}

func main() {}
