package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Q8  = bpf.Queue[uint8]{MaxEntries: 4}
	S64 = bpf.Stack[int64]{MaxEntries: 2}
	B16 = bpf.BloomFilter[uint16]{MaxEntries: 8}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 8}
)

// Positive case: three kinds, push any / exist, pop / peek, bloom push / peek, 8 to 64 bit V, a bloom without zero_seed.

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	st := Q8.Push(7, bpf.PushAny)
	st2 := Q8.Push(8, bpf.PushExist)
	v, ps := Q8.Pop()
	w, ks := S64.Peek()
	_ = S64.Push(-3, bpf.PushAny)
	_, _ = S64.Pop()
	bs := B16.Push(300)
	bp := B16.Peek(300)
	Out.Update(0, uint64(st+st2+ps+ks+bs+bp))
	Out.Update(1, uint64(v)+uint64(w))
	return bpf.XDPPass
}

func main() {}
