package bpf

import "reflect"

// UserRingBuf is a ring buffer from user space to the kernel (BPF_MAP_TYPE_USER_RINGBUF):
//
//	type Req struct{ A, B uint32 }
//	var In = bpf.UserRingBuf[Req]{MaxEntries: 4096} // a power of 2, 4096 or more (a multiple of the kernel page)
//
//	func onReq(r Req, ok bool) bool { … return stop } // the drain callback (a named function in the same package)
//	n := In.Drain(onReq)                              // eBPF side — passes the written samples to the callback one at a time
//
// The user-space side writes samples with Write of gobpf.NewUserRingWriter(&In). Drain on the eBPF side is only in a program body.
type UserRingBuf[V any] struct {
	// MaxEntries is the ring buffer size (bytes — a constant power of 2, 4096 or more, written in the declaration's composite literal).
	MaxEntries uint32
}

// Drain is eBPF side only: passes the written samples, oldest first, one at a time to callback cb (helper bpf_user_ringbuf_drain, flags 0). cb is a function in the same package of the form
// `func name(r V, ok bool) bool` — r is the sample read as V, **ok reports whether the sample covers every field of V** (the fields of a short sample are not silently
// zeroed), and returning true stops there (the stopping sample is consumed too). The body of cb may use only arithmetic, Add / Load of bpf.Global and KtimeNs (no maps).
// The return value is the number of consumed samples (including the stopping one) or a negative errno (−EBUSY: another drain is in progress, etc.). Only in the top-level flow of the program body (outside loops).
func (r *UserRingBuf[V]) Drain(cb any) int64 { panic(ebpfOnly("UserRingBuf.Drain")) }

// GobpfTypes is the binding's types (no key; the value is the sample type).
func (r *UserRingBuf[V]) GobpfTypes() (key, value reflect.Type) { return nil, reflect.TypeFor[V]() }

// GobpfMapKind is the map kind (the schema's kind).
func (r *UserRingBuf[V]) GobpfMapKind() string { return "user_ringbuf" }
