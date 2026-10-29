package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: flow_dissector — reading flow_keys (NProto, Nhoff, Flags) and writing some of the 14 scalar fields, reading a packet window,
// verdicts FlowOK / FlowDrop and FlowContinue.

func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	good := false
	if ctx.NProto() == 0x0008 && ctx.Nhoff() == 14 && ctx.Flags() == 0 {
		if w, ok := ctx.Check(14, 20); ok {
			ctx.SetIPProto(w.U8(9))
			ctx.SetIPv4Src(w.LE32(12))
			ctx.SetThoff(34)
			ctx.SetIsFrag(0)
			ctx.SetFlowLabel(0)
			good = true
		}
	}
	if good {
		return bpf.FlowOK
	}
	return bpf.FlowDrop
}

func classify(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	if ctx.NProto() == 0x0008 {
		return bpf.FlowOK
	}
	return bpf.FlowContinue
}

// allkeys reads and writes all 14 scalar fields (generation and ebpf-compile only — the differential test measures only dissect's fields).
func allkeys(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	ctx.SetNhoff(ctx.Nhoff())
	ctx.SetThoff(ctx.Thoff())
	ctx.SetAddrProto(ctx.AddrProto())
	ctx.SetIsFrag(ctx.IsFrag())
	ctx.SetIsFirstFrag(ctx.IsFirstFrag())
	ctx.SetIsEncap(ctx.IsEncap())
	ctx.SetIPProto(ctx.IPProto())
	ctx.SetNProto(ctx.NProto())
	ctx.SetSport(ctx.Sport())
	ctx.SetDport(ctx.Dport())
	ctx.SetIPv4Src(ctx.IPv4Src())
	ctx.SetIPv4Dst(ctx.IPv4Dst())
	ctx.SetFlags(ctx.Flags())
	ctx.SetFlowLabel(ctx.FlowLabel())
	return bpf.FlowContinue
}

func main() {}
