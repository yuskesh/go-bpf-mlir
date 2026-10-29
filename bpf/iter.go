package bpf

// iter programs (bpf-mlir's iter kind; the target is bpf_map_elem only):
//
//	type Line struct{ Seq, Tag uint64 }
//	var Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}
//
//	//gobpf:iter bpf_map_elem Elems
//	func dump(ctx *bpf.IterContext) {
//		if s := ctx.Seq(); s != nil {
//			_ = s.Write(Line{Seq: ctx.SeqNum(), Tag: 1})
//		}
//	}
//
// The directive's second word is the map variable the iterator walks (a bpf.Array / bpf.Hash of this package; the program does not read the elements). The program is called for each element and
// for the final stop (it cannot read elements, so it does not tell them apart), and SeqNum advances only when there is a next element (the stop call has the same value as the last element). Write writes
// all bytes of a record to the iterator output and returns the raw status (0 or −E2BIG). Attach with gobpf.AttachIter; the output is read from the returned link's Open().
// The target's arguments from the second on (the element's key and value) are not readable (bpf-mlir's scope). A non-root loader needs CAP_BPF + CAP_PERFMON.

// IterContext is the context of an iter (BPF_TRACE_ITER) program.
type IterContext struct{ _ [0]func() }

// SeqFile is the iterator output (the kernel's struct seq_file — a local type; no field is read). It is used only through Write on the checked pointer from ctx.Seq().
type SeqFile struct {
	_    Kernel `kernel:"seq_file"`
	size uint64 `kernel:"size"`
}

// SeqNum is the iterator's 0-based number (seq_num of bpf_iter_meta — it advances only when there is a next element). Only at the top level of the program body.
func (c *IterContext) SeqNum() uint64 { panic(ebpfOnly("IterContext.SeqNum")) }

// Seq is the iterator output (seq of bpf_iter_meta — it can be NULL). Only in the shape `if s := ctx.Seq(); s != nil { … }`.
func (c *IterContext) Seq() *SeqFile { panic(ebpfOnly("IterContext.Seq")) }

// Write writes all bytes of the record value rec to the iterator output (helper seq_write). Raw status — 0 is success, negative is −errno (−E2BIG means the output buffer
// overflowed). rec is a composite literal of the record struct.
func (s *SeqFile) Write(rec any) int64 { panic(ebpfOnly("SeqFile.Write")) }
