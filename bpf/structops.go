package bpf

import "reflect"

// struct_ops tcp_congestion_ops (bpf-mlir's struct_ops map kind and struct_ops program kind):
//
//	var CC = bpf.TCPCongestionOps{Name: "gobpf_cc"}
//
//	//gobpf:struct_ops CC init
//	func ccInit(ctx *bpf.StructOpsContext) { … }
//
//	//gobpf:struct_ops CC ssthresh
//	func ccSsthresh(ctx *bpf.StructOpsContext) uint32 { return 2 }
//
//	//gobpf:struct_ops CC undo_cwnd
//	func ccUndo(ctx *bpf.StructOpsContext) uint32 { return 10 }
//
//	//gobpf:struct_ops CC cong_avoid
//	func ccCongAvoid(ctx *bpf.StructOpsContext) { … }
//
// A TCPCongestionOps variable is the struct_ops map (one per package), and a function with `//gobpf:struct_ops <map> <member>` is the program for that member.
// The members are only init (no result), ssthresh (uint32), undo_cwnd (uint32) and cong_avoid (no result), and **ssthresh, undo_cwnd and cong_avoid are required**
// (the kernel's tcp_validate_congestion_control needs them — a missing one stops at generate). gobpf.Load writes the value to the map but **does not register it** (BPF_F_LINK);
// gobpf.AttachStructOps registers it (it becomes one of the kernel's TCP congestion control names — **a system-wide name that sockets in every netns can
// select with setsockopt TCP_CONGESTION**), and closing the link removes it. A non-root loader needs CAP_BPF + CAP_PERFMON; a socket that selects the name needs CAP_NET_ADMIN.

// TCPCongestionOps is the declaration of a tcp_congestion_ops struct_ops map. Name is the registered name (a constant of 1 to 15 characters of [A-Za-z0-9_.] — the kernel's
// TCP_CA_NAME_MAX 16 minus the terminator; setsockopt TCP_CONGESTION copies up to 15 characters).
type TCPCongestionOps struct {
	// Name is the registered name (the name shown in tcp_available_congestion_control — selected with setsockopt TCP_CONGESTION).
	Name string
}

// StructOpsContext is the context of a struct_ops program (the member's arguments — StructOpsArg / StructOpsArgInt).
type StructOpsContext struct{ _ [0]func() }

// StructOpsArg is eBPF side only: returns the member's struct argument i (for tcp_congestion_ops members, i = 0 is `struct sock *` — the verifier promotes it to tcp_sock,
// so T is a local type with tag `kernel:"tcp_sock"`) as a pointer to the kernel's struct T (ebpf.ctx.arg). **It can always be
// NULL**, so use it only in the shape `if sk := bpf.StructOpsArg[T](ctx, 0); sk != nil { … }` (kptr.check). In a struct_ops program you **can assign to integer
// fields** (`sk.SndCwnd = n` — ebpf.kfield.store, with the declared width) — the kernel decides which fields are writable (for tcp_sock: snd_cwnd, snd_ssthresh,
// snd_cwnd_cnt, etc. — the load verifier refuses writes to other fields).
func StructOpsArg[T any](ctx *StructOpsContext, i uint32) *T { panic(ebpfOnly("StructOpsArg")) }

// StructOpsArgInt is eBPF side only: the value of the member's integer argument i (ebpf.ctx.arg — cong_avoid's 1 = ack, 2 = acked; T is uint32). Only the shape
// `x := bpf.StructOpsArgInt[T](ctx, i)` at the top level of the program body (the same as FentryArgInt).
func StructOpsArgInt[T KprobeInt](ctx *StructOpsContext, i uint32) T {
	panic(ebpfOnly("StructOpsArgInt"))
}

// GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and there is no value (the kernel's bpf_struct_ops_<type> — the loader writes it).
func (m *TCPCongestionOps) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), nil
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *TCPCongestionOps) GobpfMapKind() string { return "struct_ops" }

// GobpfMaxEntries is an internal API of the gobpf runtime — a struct_ops map has no MaxEntries field and is 1 (one value at key 0).
func (m *TCPCongestionOps) GobpfMaxEntries() uint32 { return 1 }

// GobpfStructOps is an internal API of the gobpf runtime — the struct_ops type and the registered name.
func (m *TCPCongestionOps) GobpfStructOps() (typ, name string) { return "tcp_congestion_ops", m.Name }
