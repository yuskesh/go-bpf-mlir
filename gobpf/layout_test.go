package gobpf

import (
	"testing"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

// The layout check before load (no root needed — it stops before any kernel object is created).
// The embedded object is the generated files of internal/difftest/rec (maps In / Out of record Rec). The test types are lRec with the same layout as Rec, and mismatching types.

type lRec struct {
	Len    uint32 `schema:"len"`
	Tiny   uint8  `schema:"tiny"`
	Small  uint8  `schema:"small"`
	Short  int16  `schema:"short"`
	Signed int32  `schema:"signed"`
	_      [4]byte
	Total  uint64    `schema:"total"`
	Hist   [4]uint16 `schema:"hist"`
	Count  int64     `schema:"count"`
}

// Integer maps too: a build whose Go declaration alone changed after generation (value width or sign, MaxEntries) stops before load.
// The embedded object is examples/xdpcount (Counts is bpf.Array[uint32, uint64]{MaxEntries: 2} — the ELF's requirements row is u32 / u64 / 2).
// K is bpf.Key32 (~uint32), so the only K difference that passes Go's type check is within the u32 spelling (a named type) — the spelling is the same, so it passes (a positive control).
func TestIntegerMapDeclChangedRefused(t *testing.T) {
	type namedKey uint32
	var (
		wide    = bpf.Array[uint32, uint64]{MaxEntries: 2}
		narrow  = bpf.Array[uint32, uint32]{MaxEntries: 2}
		signed  = bpf.Array[uint32, int64]{MaxEntries: 2}
		bigger  = bpf.Array[uint32, uint64]{MaxEntries: 3}
		named   = bpf.Array[namedKey, uint64]{MaxEntries: 2}
		wrongRB = bpf.RingBuf[lRec]{MaxEntries: 4096}
	)
	cases := []struct {
		name string
		v    any
		want string // the mismatching field (the Field of bindrt's MapDeclProblem); "" passes
	}{
		{"same", &wide, ""},
		{"named_key", &named, ""},
		{"value_width", &narrow, "value"},
		{"value_sign", &signed, "value"},
		{"max_entries", &bigger, "max_entries"},
		{"kind_changed", &wrongRB, "kind"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset(t)
			o := exampleObject(t)
			o.Maps = []Map{{Symbol: "Counts", Var: c.v}}
			Register(o)
			_, err := LoadCollectionSpec()
			if c.want == "" {
				if err != nil {
					t.Fatalf("must pass: %v", err)
				}
				return
			}
			wantMapDecl(t, err, "Counts", c.want)
			t.Logf("%s: %v", c.name, err)
		})
	}
}
