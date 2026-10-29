package bpf

// Ring buffer reservation (bpf-mlir's reservation feature):
//
//	if e, ok := Events.Reserve(); ok {
//		e.Kind = k            // assign an integer field (write only — a reservation cannot be read)
//		if k == 1 {
//			Events.Discard(e) // discard (the reader does not see it)
//		} else {
//			Events.Submit(e)  // commit (the reader sees it)
//		}
//	} else {
//		// the ring buffer had no free space
//	}
//
// e is created only by Reserve in the if's init statement and used only in integer field assignments, `*e = V{…}` and as the argument of Submit / Discard (reads, other variables, passing to functions,
// the else arm, inside a loop and defer are stopped by the frontend). **On every path of the present arm, Submit or Discard exactly once** — a double use, a miss, or an assignment after
// consumption is stopped by bpf-mlir's ownership check at go generate, with the Go position.

// Reserve is eBPF side only: reserves a region of V's size in the ring buffer and, if it got one, returns the reservation handle and true (otherwise nil and false).
// Only in the init statement shape `if e, ok := r.Reserve(); ok { … }`.
func (r *RingBuf[V]) Reserve() (*V, bool) { panic(ebpfOnly("RingBuf.Reserve")) }

// Submit is eBPF side only: commits reservation e and shows it to the reader (this consumes the reservation — e cannot be used afterwards).
func (r *RingBuf[V]) Submit(e *V) { panic(ebpfOnly("RingBuf.Submit")) }

// Discard is eBPF side only: discards reservation e (the reader does not see it — this consumes the reservation; e cannot be used afterwards).
func (r *RingBuf[V]) Discard(e *V) { panic(ebpfOnly("RingBuf.Discard")) }
