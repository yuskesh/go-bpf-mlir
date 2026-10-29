package main

import (
	"encoding/binary"
	"testing"
)

// The -selftest expected table (a hand-written oracle) matches the eBPF side's classify and the program's length rule evaluated in Go.
// This file is outside the frontend's analysis (Tests: false), so it can call the eBPF-side functions with Go semantics. It does not use the kernel.
func TestSelftestTableMatchesClassify(t *testing.T) {
	for _, f := range selftestFrames() {
		key := KShort
		if len(f.frame) >= 14 {
			et := binary.BigEndian.Uint16(f.frame[12:])
			key = classify(et, 0)
			if et == 0x0800 {
				key = KIPv4Short
				if len(f.frame) >= 24 {
					key = classify(et, f.frame[23])
				}
			}
		}
		if key != f.key {
			t.Errorf("%s: the table says %s, classify says %s", f.name, keyNames[f.key], keyNames[key])
		}
	}
}
