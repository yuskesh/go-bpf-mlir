package frontend

import (
	"fmt"
	"go/token"
	"sort"
	"strings"
)

// Verdict is one of the four verdict values (the same meaning as bpf-mlir's CheckResult.h).
//
//   - Verified: a shape in the table, accepted
//   - Rejected: refused by a known rule (misuse of the other side's API, outside the nil check shape, and so on)
//   - Conditional: accepted with a condition (not used in the first version — only the type exists)
//   - Unknown: not in the table (fail closed — anything unknown does not pass)
//
// Anything other than Verified and Conditional stops generation.
type Verdict int

const (
	Verified Verdict = iota
	Rejected
	Conditional
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Verified:
		return "verified"
	case Rejected:
		return "rejected"
	case Conditional:
		return "conditional"
	case Unknown:
		return "unknown"
	}
	return fmt.Sprintf("verdict(%d)", int(v))
}

// Code is a reason code. **Codes may be added, but their meaning never changes.**
type Code string

const (
	GB000TypeCheck             Code = "GB000" // a Go type error (including references to generated identifiers)
	GB001UnsupportedConstruct  Code = "GB001" // a construct not in the table
	GB002UnsupportedCall       Code = "GB002" // a call or identifier not in the table
	GB003CrossDomainUse        Code = "GB003" // use of the other side's API
	GB004UnknownEdge           Code = "GB004" // an edge that cannot be followed statically (function values, method values, interfaces)
	GB005NilCheckShape         Code = "GB005" // outside the nil check shape
	GB006NonConstant           Code = "GB006" // a non-constant where a constant is required
	GB007ReservedName          Code = "GB007" // the reserved prefix gobpf_
	GB008ProgramShape          Code = "GB008" // has a context parameter but is not a program shape
	GB009MapDeclShape          Code = "GB009" // outside the map declaration shape
	GB010Recursion             Code = "GB010" // recursion in eBPF side functions (with the cycle path)
	GB011CapabilityNotProvided Code = "GB011" // a capability the root's kind does not provide (with the path)
	GB012IntegerRule           Code = "GB012" // an integer rule (shift count, divisor)
	GB013SubprogramShape       Code = "GB013" // outside the subprogram shape (arguments, results, values that cannot be passed)
	GB014WindowIndex           Code = "GB014" // a packet window index out of range
	GB015InternalEmitter       Code = "GB015" // an internal frontend error (the emitter fails closed)
	GB016SharedABIShape        Code = "GB016" // outside the shared type shape (SharedABI — record / array)
	GB017StatusIgnored         Code = "GB017" // an expression statement discarding a map operation's status (int64) (make it explicit with `_ =`)
	GB018LoopShape             Code = "GB018" // outside the bounded loop shape (constant count ≤ 64, nesting 2, things not allowed in the body)
	GB019ExportedBPFFunc       Code = "GB019" // an exported eBPF side function outside package main (a path to a stub panic when called from another package)
	GB020ArrayKeyUnproven      Code = "GB020" // an Array variable key that cannot be proven below MaxEntries (Conditional — out of range silently does nothing)
	GB021AtomicShape           Code = "GB021" // outside the bpf.AtomicAdd use shape (other than &p.F, an array element, an offset not a multiple of the width)
	GB022LocRange              Code = "GB022" // an op loc outside the range of BTF line_info (column > 1023, line > 2^20 — bpf-mlir refuses it)
	GB023TailShape             Code = "GB023" // outside the shape of prog_array slot declarations (bpf.TailSlot) and tail calls (TailCall / TailCallIf)
	GB024CompileWarning        Code = "GB024" // an ebpf-compile warning (rc 0 — a ref.index index reached by a constant and an unknown value on different paths); Conditional
	GB025PacketWrite           Code = "GB025" // outside the XDP packet rewrite shape (writes to a sched_cls window, an old window after a helper, a positive AdjustTail delta)
	GB026LockTimerShape        Code = "GB026" // outside the spin lock / timer shape (calls, escapes and outer assignments in a WithLock region, starting outside Init == 0, the callback shape, other than xdp)
	GB027KernelTypeShape       Code = "GB027" // outside the shape of tp_btf and kernel struct local types (the TPArg shape, kernel type declarations, uses of a kernel pointer other than reads)
	GB028NonAtomicRMW          Code = "GB028" // a non-atomic read-modify-write of a shared (not per-CPU) map value (op=, ++, = reading the same path back, Update with a value of the same map)
	GB029BorrowAlias           Code = "GB029" // two borrows may point at the same value (same map with keys not shown to be different constants, a Lookup inside a borrow argument of the same type)
)

var codeNames = map[Code]string{
	GB000TypeCheck:             "TypeCheck",
	GB001UnsupportedConstruct:  "UnsupportedConstruct",
	GB002UnsupportedCall:       "UnsupportedCall",
	GB003CrossDomainUse:        "CrossDomainUse",
	GB004UnknownEdge:           "UnknownEdge",
	GB005NilCheckShape:         "NilCheckShape",
	GB006NonConstant:           "NonConstant",
	GB007ReservedName:          "ReservedName",
	GB008ProgramShape:          "ProgramShape",
	GB009MapDeclShape:          "MapDeclShape",
	GB010Recursion:             "Recursion",
	GB011CapabilityNotProvided: "CapabilityNotProvided",
	GB012IntegerRule:           "IntegerRule",
	GB013SubprogramShape:       "SubprogramShape",
	GB014WindowIndex:           "WindowIndex",
	GB015InternalEmitter:       "InternalEmitter",
	GB016SharedABIShape:        "SharedABIShape",
	GB017StatusIgnored:         "StatusIgnored",
	GB018LoopShape:             "LoopShape",
	GB019ExportedBPFFunc:       "ExportedBPFFunc",
	GB020ArrayKeyUnproven:      "ArrayKeyUnproven",
	GB021AtomicShape:           "AtomicShape",
	GB022LocRange:              "LocRange",
	GB023TailShape:             "TailShape",
	GB024CompileWarning:        "CompileWarning",
	GB025PacketWrite:           "PacketWrite",
	GB026LockTimerShape:        "LockTimerShape",
	GB027KernelTypeShape:       "KernelTypeShape",
	GB028NonAtomicRMW:          "NonAtomicRMW",
	GB029BorrowAlias:           "BorrowAlias",
}

// Diagnostic is one verdict. Its message text (String) is built from this type.
type Diagnostic struct {
	Verdict Verdict
	Code    Code
	Pos     token.Position // Filename is relative to the package directory
	Path    []string       // the call path (for example [CountPackets, Counts.Get])
	Msg     string
}

func (d Diagnostic) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:%d:%d: %s %s %s: %s", d.Pos.Filename, d.Pos.Line, d.Pos.Column, d.Code, codeNames[d.Code], d.Verdict, d.Msg)
	if len(d.Path) > 0 {
		fmt.Fprintf(&b, " [path: %s]", strings.Join(d.Path, " → "))
	}
	return b.String()
}

// Blocks reports whether the verdict stops generation.
func (d Diagnostic) Blocks() bool { return d.Verdict == Rejected || d.Verdict == Unknown }

func sortDiagnostics(ds []Diagnostic) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i].Pos, ds[j].Pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if ds[i].Code != ds[j].Code {
			return ds[i].Code < ds[j].Code
		}
		// diagnostics with the same position and code are ordered by message (the output order is fixed even where the report order depends on Go map iteration)
		return ds[i].Msg < ds[j].Msg
	})
}

// codeFixes is the fix for each reason code (shown in the user-facing reference codes.md). **When adding a new code, add its fix too**
// (TestReferenceCodes names any missing one).
var codeFixes = map[Code]string{
	GB000TypeCheck:             "fix the Go type error (the same message as go build). Do not refer to identifiers of the generated file (`gobpf_…`) from the source",
	GB001UnsupportedConstruct:  "rewrite it in a form the table has — for example: return only as the last statement of a program, a side-effect-free expression on the right of && / ||, a chain of if statements instead of switch",
	GB002UnsupportedCall:       "use only the bpf / gobpf identifiers listed in docs/reference/api.md (an identifier not in the table stops, fail closed)",
	GB003CrossDomainUse:        "use eBPF-side operations in functions reachable from a program, and user-space operations (Get / Put / Load …) in functions not reachable from a program. Split a function called from both",
	GB004UnknownEdge:           "use a program function value only as an argument of gobpf.AttachXDP / AttachTCX / AttachFentry / AttachFexit, Objects.Program and bpf.TailSlot. Call a method value directly",
	GB005NilCheckShape:         "use the form `if p := M.Lookup(k); p != nil { … }` / `if w, ok := ctx.Check(off, n); ok { … }`, and use the checked value only inside the checked branch",
	GB006NonConstant:           "write a constant (MaxEntries, the verdict, the Check length, the window index, the AdjustTail delta, the TailSlot slot, the else verdict)",
	GB007ReservedName:          "do not use names starting with `gobpf_` (the generated file uses them)",
	GB008ProgramShape:          "a program is a top-level `func(ctx *bpf.<Context>) <verdict type>` (fentry / fexit have no result and take a directive) — docs/reference/kinds.md",
	GB009MapDeclShape:          "declare a map at package level as `var M = bpf.<Map>[K, V]{MaxEntries: N}` and use it only as a method receiver (no assignment, address or copy)",
	GB010Recursion:             "remove the cycle of eBPF-side function calls (BPF-to-BPF calls cannot recurse)",
	GB011CapabilityNotProvided: "remove from the functions on the path the constructs whose capability the kind does not provide (heap, string, float, goroutine, unbounded loop …) — the capabilities in docs/reference/kinds.md",
	GB012IntegerRule:           "make the shift count a constant within the width and the divisor a non-zero constant (a signed −1 is not allowed — MinInt / −1)",
	GB013SubprogramShape:       "a subprogram takes up to five arguments (integers and bool, the program context as the first argument, one packet window, one borrowed map value) and one result, ending in `return <value>` — move the form the message names (forwarding, a global's context, an attach-specific read, …) to the caller",
	GB014WindowIndex:           "make the window read / write index a constant within the Check length (i + width ≤ n). Lengthen the Check if it is too short",
	GB015InternalEmitter:       "nothing for the user to fix — a frontend bug. Report it with the input Go source",
	GB016SharedABIShape:        "a record is a named struct of the same package whose fields are fixed-width integers or arrays of them, every field has a `schema:\"…\"` tag, and padding is an explicit `_ [N]byte`. When ebpf-compile stops a function at the BPF stack limit and that function writes a ring buffer event whose record has `_` padding, generate names the padding as the likely cause: give the padding field a name (for example `Pad uint32` with a schema tag) so the event is stored straight into the reservation",
	GB017StatusIgnored:         "use the status (int64 — 0 or a negative errno), or discard it explicitly with `_ = …` (for Output: the result or CountDropsIn)",
	GB018LoopShape:             "`for i := range uint32(N)` / `for i := T(0); i < N; i++` (a constant N ≤ 64, nesting 2, product ≤ 64), break / continue as the last statement of an if / Check branch, an unroll estimate of at most 4096 — make the body smaller or lower N",
	GB019ExportedBPFFunc:       "give eBPF-side functions outside package main lower-case names (attach from a user-space function of the same package)",
	GB020ArrayKeyUnproven:      "generation does not stop (Conditional). Prove the key in range by clamping it with `if k >= N { k = N - 1 }` or masking it with `k & (2^j - 1)` — an out-of-range key silently does nothing",
	GB021AtomicShape:           "use the form `bpf.AtomicAdd(&p.F, d)` where p is a checked record pointer and F a 32 / 64-bit integer field (not an array element)",
	GB022LocRange:              "shorten the line (column ≤ 1023, line ≤ 2^20 — the width of BTF line_info) or generate with `go tool gobpf -line-info=off`",
	GB023TailShape:             "a slot is `var _ = bpf.TailSlot(&M, constant, Prog)` (an xdp program of the same package), and TailCall / TailCallIf is one top-level statement of an xdp program's body",
	GB024CompileWarning:        "generation does not stop (Conditional). Follow the ebpf-compile warning and its note location — for example: do not let a constant default flow into a ref.index index (use the index inside the Lookup's checked branch). For a mask-range warning, leave room after the record array up to the next power-of-two element count (`_ [N]byte`)",
	GB025PacketWrite:           "packet writes are for xdp programs only. Re-create the window with ctx.Check after an Adjust. The AdjustTail delta is 0 or less",
	GB026LockTimerShape:        "inside the WithLock func, only reads and writes of fields of the same p and integer arithmetic. SetCallback / Start go inside `if st := p.T.Init(); st == 0 { … }`. A callback is func(v *V) using only v's fields and bpf.KtimeNs. Lock / timer ops are for xdp programs only",
	GB027KernelTypeShape:       "a kernel type has the blank-field marker `_ bpf.Kernel` (tag kernel:\"<struct>\") and int32 / uint32 fields (each with tag kernel:\"<field>\"). TPArg is a top-level `p := bpf.TPArg[T](ctx, i)` in a tp_btf body (earlier arguments not read are `_ =`), and p is only used for field reads",
	GB028NonAtomicRMW:          "reading a shared map value and writing it back (`p.N += d`, `p.N++`, `x := p.N; p.N = x + 1`, `M.Update(k, *p + 1)`) loses counts on several CPUs. For addition use `bpf.AtomicAdd(&p.N, d)` / `M.AtomicAdd(k, d)`, for per-CPU counts a per-CPU map, for updating several fields together `bpf.WithLock(&p.Lock, func() { … })` in xdp. For copies, read and write different maps or keys that are provably different (different constants)",
	GB029BorrowAlias:           "copy the values you need into local variables before the second Lookup (`v := p.F`, close p's branch, then `if q := M.Lookup(k2); q != nil { … }`). To hold two at once, use different maps or different constant keys of the same map (`M.Lookup(0)` and `M.Lookup(1)`)",
}

// codeExampleElsewhere is where the example comes from for codes without an example in the TestNegative table.
var codeExampleElsewhere = map[Code]string{
	GB002UnsupportedCall:  "`TestFailClosed` (removing bpf.Array.Update from the table turns its use in examples/xdpcount into an Unknown GB002 — \"bpf.Array.Update is not in gobpf's API table\". Every exported bpf identifier is in the table, so no testdata negative case can be written)",
	GB015InternalEmitter:  "assumed unreachable — `TestInternalEmitterUnreachable` checks that no input in the repository produces it",
	GB020ArrayKeyUnproven: "`internal/frontend/testdata/keyproof_cond` (Conditional — a golden line of `TestConditionalGolden`)",
	GB022LocRange:         "`TestLongLineLocRange` (the test creates a temporary package with a 1100-column line — `main.go:13:1125`)",
	GB024CompileWarning:   "a constant default that reaches a ref.index index, and the mask range of a trailing [5]uint32 in a record — both appear in the conditional section of the generated file and in the Conditional golden lines",
}
