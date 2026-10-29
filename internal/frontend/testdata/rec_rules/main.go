package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Gap struct {
	A uint8  `schema:"a"`
	B uint32 `schema:"b"`
}

type Tail struct {
	A uint64 `schema:"a"`
	B uint8  `schema:"b"`
}

type NoTag struct {
	A uint32
}

type Unexported struct {
	a uint32 `schema:"a"`
}

type Flag struct {
	On bool `schema:"on"`
	_  [7]byte
}

type Ptr struct {
	P *uint64 `schema:"p"`
}

type Slice struct {
	S []uint8 `schema:"s"`
}

type Str struct {
	S string `schema:"s"`
}

type Float struct {
	F float64 `schema:"f"`
}

type Word struct {
	N uint `schema:"n"`
}

type Nested struct {
	G Gap2 `schema:"g"`
}

type Gap2 struct {
	A uint32 `schema:"a"`
}

type Dup struct {
	A uint32 `schema:"x"`
	B uint32 `schema:"x"`
}

type BadPad struct {
	A uint16 `schema:"a"`
	_ [1]uint16
}

type Named uint64

var (
	M1  = bpf.Array[uint32, Gap]{MaxEntries: 1}
	M2  = bpf.Array[uint32, Tail]{MaxEntries: 1}
	M3  = bpf.Array[uint32, NoTag]{MaxEntries: 1}
	M4  = bpf.Array[uint32, Unexported]{MaxEntries: 1}
	M5  = bpf.Array[uint32, Flag]{MaxEntries: 1}
	M6  = bpf.Array[uint32, Ptr]{MaxEntries: 1}
	M7  = bpf.Array[uint32, Slice]{MaxEntries: 1}
	M8  = bpf.Array[uint32, Str]{MaxEntries: 1}
	M9  = bpf.Array[uint32, Float]{MaxEntries: 1}
	M10 = bpf.Array[uint32, Word]{MaxEntries: 1}
	M11 = bpf.Array[uint32, Nested]{MaxEntries: 1}
	M12 = bpf.Array[uint32, Dup]{MaxEntries: 1}
	M13 = bpf.Array[uint32, BadPad]{MaxEntries: 1}
	M14 = bpf.Array[uint32, [4]uint32]{MaxEntries: 1}
	M15 = bpf.Array[uint32, uint16]{MaxEntries: 1}
	M16 = bpf.Array[uint32, struct {
		A uint32 `schema:"a"`
	}]{MaxEntries: 1}
	M17 = bpf.Array[uint32, Named]{MaxEntries: 1}
)

func P(ctx *bpf.XDPContext) bpf.XDPAction { return bpf.XDPPass }

func main() {}
