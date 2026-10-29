package main

import (
	"encoding/binary"
	"testing"
)

// The -selftest expected table (a hand-written oracle) matches the eBPF side's classify and the program's rules (the 34-byte window, flows with IHL 5,
// ports at a variable offset) evaluated in Go (the kernel is not used).
func TestSelftestTableMatchesProgram(t *testing.T) {
	for _, f := range selftestFrames() {
		key := KOther
		var ev *Event
		var flow *FlowKey
		ihl := false
		if len(f.frame) >= 34 && binary.BigEndian.Uint16(f.frame[12:]) == 0x0800 {
			proto := f.frame[23]
			key = classify(proto)
			ev = &Event{Len: binary.BigEndian.Uint16(f.frame[16:]), EtherType: 0x0800, Proto: proto, TTL: f.frame[22], Src: [4]uint8(f.frame[26:30])}
			if h := int(f.frame[14] & 0x0f); h >= 5 {
				var sport, dport uint16
				if off := 14 + h*4; (proto == 6 || proto == 17) && off+4 <= len(f.frame) {
					sport, dport = binary.BigEndian.Uint16(f.frame[off:]), binary.BigEndian.Uint16(f.frame[off+2:])
				}
				flow = &FlowKey{Addr: Addrs{Src: [4]uint8(f.frame[26:30]), Dst: [4]uint8(f.frame[30:34])}, Port: Ports{Src: sport, Dst: dport}, Proto: proto}
			} else {
				ihl = true
			}
		}
		if key != f.key {
			t.Errorf("%s: the table says %s, the program says %s", f.name, keyNames[f.key], keyNames[key])
		}
		if (ev == nil) != (f.event == nil) || (ev != nil && *ev != *f.event) {
			t.Errorf("%s: the table's event %+v, the program's %+v", f.name, f.event, ev)
		}
		if (flow == nil) != (f.flow == nil) || (flow != nil && *flow != *f.flow) {
			t.Errorf("%s: the table's flow %+v, the program's %+v", f.name, f.flow, flow)
		}
		if ihl != f.ihl {
			t.Errorf("%s: the table's ihl %v, the program's %v", f.name, f.ihl, ihl)
		}
	}
}

// The boundaries of the length-distribution bucket rule (sizeBucket — the selftest's expected values) are compared with hand-written values.
func TestSizeBucketBoundaries(t *testing.T) {
	for _, c := range []struct{ ln, b uint32 }{{0, 0}, {64, 0}, {65, 1}, {128, 1}, {129, 2}, {1500, 5}, {4096, 6}, {4097, 7}, {65535, 7}} {
		if got := sizeBucket(c.ln); got != c.b {
			t.Errorf("sizeBucket(%d) = %d, want %d", c.ln, got, c.b)
		}
	}
}
