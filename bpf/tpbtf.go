package bpf

// tp_btf and CO-RE kernel struct fields (bpf-mlir's ebpf.ctx.arg and ebpf.kfield.load).

// TPBTFContext is the context of a tp_btf (raw tracepoint with BTF types) program. A function whose first parameter has this type and that has no result becomes a tp_btf
// program, and the tracepoint name is written in the directive just before the function declaration:
//
//	//gobpf:tp_btf sched_process_fork
//	func onFork(ctx *bpf.TPBTFContext) { parent := bpf.TPArg[Task](ctx, 0); … parent.Tgid … }
//
// Attach with gobpf.AttachTPBTF; a non-root loader needs CAP_BPF + CAP_PERFMON. **On a 6.6 kernel, a tp_btf program that reads a struct (pointer) argument
// cannot be loaded** (the 6.6 verifier does not mark arguments that can be NULL, and a NULL read silently becomes 0 — gobpf.Load's check (arg_nullable) stops it with a named error).
// A program that reads only integer arguments (TPArgInt) can be loaded on 6.6 too.
// Note (2026-09-27, from reading the kernel source): on 6.6, reading an argument that can be NULL without a check is expected to be a kernel NULL dereference rather than a "silent 0", since a trusted pointer load is not PROBE_MEM (not verified at run time — bpf-mlir deliberately builds no program that triggers it). The stopping check (arg_nullable) is the same.
type TPBTFContext struct{ _ [0]func() }

// Kernel is the marker of a local declaration of a kernel struct (size 0). Write it on a blank field with tag `kernel:"<kernel struct name>"`:
//
//	type Task struct {
//		_    bpf.Kernel `kernel:"task_struct"`
//		Pid  int32      `kernel:"pid"`
//		Tgid int32      `kernel:"tgid"`
//	}
//
// Every other field has tag `kernel:"<field name>"`, and its type is **int8 to int64 / uint8 to uint64** (kfield.load — the width and sign must match
// the target kernel's type), **`[N]byte` / `[N]int8` (1 ≤ N ≤ 64)** (a char array — only a copy `q.Comm = p.Comm` into a same-typed field of a checked record
// — kfield.copy), or **`*U`** (U is also a local kernel type — following a pointer field. It can always be NULL, so read it only in the shape `if m := p.MM; m != nil { … }`
// — kfield.ptr and kptr.check). Declaring only the fields you read is enough,
// and the offset is unrelated to the Go layout — it is decided at load from the target kernel's BTF (CO-RE). A missing field or a width or sign mismatch is stopped with a named error by gobpf.Load's
// check (kfield) (**LoadUnchecked does not check** — cilium's CO-RE silently turns a missing field into an invalid instruction and does not look at width or sign).
// This type cannot be used in a record, a map value or an event.
type Kernel struct{}

// TPArg is eBPF side only: returns argument i (a constant 0..11) of the tp_btf tracepoint as a pointer to the kernel's struct T (ebpf.ctx.arg).
// Only the shape `p := bpf.TPArg[T](ctx, i)` at the top level of the program body. **Declare the types of all arguments before the largest i you read** — for an argument you do not read, write
// `_ = bpf.TPArg[T](ctx, j)` (tracepoint arguments are checked in position order as struct pointers — arguments after an integer argument of a tracepoint cannot be read yet).
// The returned pointer is **read only**: `p.F` (a field read — each read is one CO-RE load). Writes, `&p.F`, `*p`, passing to a function and reassignment are stopped by the frontend.
// Reads inside a loop body are not allowed either. **Earlier arguments you do not read need no declaration** (schema null; a type declaration `_ = bpf.TPArg[T](ctx, j)` is also accepted).
// **An argument that can be NULL** is written in the shape `if p := bpf.TPArg[T](ctx, i); p != nil { … } [else { … }]` — the schema declares the argument nullable, and
// kptr.check (on a 6.6 kernel the gate's arg_nullable stops before load regardless of the check).
func TPArg[T any](ctx *TPBTFContext, i uint32) *T { panic(ebpfOnly("TPArg")) }

// TPArgInt is eBPF side only: the value of the tp_btf tracepoint's integer argument i (a constant 0..11) (ebpf.ctx.arg). T is int8 to uint64 with the same width and sign as the target's argument
// (gobpf.Load's check stops a width or sign mismatch with a named error). Only the shape `x := bpf.TPArgInt[T](ctx, i)` at the top level of the program body.
func TPArgInt[T KprobeInt](ctx *TPBTFContext, i uint32) T { panic(ebpfOnly("TPArgInt")) }

// FentryArg is eBPF side only: returns argument i (a constant 0..11) of the fentry program's attached function as a pointer to the kernel's struct T (ebpf.ctx.arg —
// bpf-mlir's fentry arguments). T is a local kernel type. **It can always be NULL**, so read it only in the shape `if p := bpf.FentryArg[T](ctx, i); p != nil { … } [else { … }]`
// (kptr.check). The argument types are checked before load against the target kernel's BTF (requirements farg rows — gobpf.Load's check).
func FentryArg[T any](ctx *FentryContext, i uint32) *T { panic(ebpfOnly("FentryArg")) }

// FentryArgInt is eBPF side only: the value of the fentry program's attached function's integer argument i (a constant 0..11) (ebpf.ctx.arg — from the 8-byte slot to T's width,
// bpf-mlir's integer fentry arguments). T is int8 to uint64 with the same width and sign as the target's argument — **the kernel's char is unsigned** (write uint8), and a mismatch is
// stopped with a named error by gobpf.Load's check (requirements farg and the target BTF's func_param). Only the shape `x := bpf.FentryArgInt[T](ctx, i)` at the top level of the program body
// (the same as TPArgInt). Earlier arguments you do not read need no declaration. It may be mixed with FentryArg in the same program (one declaration per argument).
func FentryArgInt[T KprobeInt](ctx *FentryContext, i uint32) T { panic(ebpfOnly("FentryArgInt")) }

// KernelAddr is eBPF side only: all 64 address bits of a checked kernel pointer p as an integer (ebpf.kptr.addr — bpf-mlir v1.16). p is a variable holding a checked pointer
// of a local kernel type (the present arm of `if p := bpf.FentryArg[T](ctx, i); p != nil`, a non-nullable bpf.TPArg, `if m := p.F; m != nil`, an iter seq), written directly.
// Only in the body of a tp_btf, fentry, fexit, iter, fmod_ret or fsession program, outside loops. The pointee is not read. The value is for correlating live objects
// (map keys, event fields, comparing two paths to the same object) — it says nothing once the object is freed (an address may be reused), and there is no conversion back to a pointer.
// Storing it in a map needs CAP_PERFMON, as loading a tracing program does.
func KernelAddr[T any](p *T) uint64 { panic(ebpfOnly("KernelAddr")) }
