package frontend

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot is the module root (two levels above this file).
func repoRoot(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func exampleDir(t *testing.T) string { return filepath.Join(repoRoot(t), "examples", "xdpcount") }

func analyzeOK(t *testing.T, dir string) *Result {
	t.Helper()
	res, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatalf("unexpected blocking diagnostics in %s", dir)
	}
	return res
}

// Two analyses of the same source give byte-identical .mlir and schema, equal to the committed outputs (golden).
func TestGoldenReproducible(t *testing.T) {
	dir := exampleDir(t)
	r1 := analyzeOK(t, dir)
	r2 := analyzeOK(t, dir)
	if !bytes.Equal(r1.MLIR, r2.MLIR) || !bytes.Equal(r1.Schema, r2.Schema) {
		t.Fatal("two runs on the same source produced different .mlir / schema")
	}
	for name, got := range map[string][]byte{"gobpf.mlir": r1.MLIR, "gobpf.schema.json": r1.Schema} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the committed golden (regenerate with go generate and record the reason in an Edoc)", name)
		}
	}
}

// negCase is one negative test (testdata package, reason code, verdict, position, message part).
type negCase struct {
	dir     string
	code    Code
	verdict Verdict
	pos     string // file:line:col
	msg     string // substring match
}

// negativeCases is the table of negative tests — shared by TestNegative and the "stopping examples" of the reference codes.md.
var negativeCases = []negCase{
	{"unsupported_stmt", GB018LoopShape, Rejected, "main.go:8:2", "the loop variable i has type int — it must be uint32 or int32"}, // a bounded-shape loop is GB018 (formerly GB011, outside capability)
	{"loop_unbounded", GB011CapabilityNotProvided, Rejected, "main.go:9:2", `needs capability "go.unbounded_loop"`},
	{"deref_in_else", GB005NilCheckShape, Rejected, "main.go:10:21", "use of p outside the checked branch"},
	{"nil_check_inverted", GB005NilCheckShape, Rejected, "main.go:8:28", "the condition must be exactly `p != nil`"},
	{"user_calls_ebpf_method", GB003CrossDomainUse, Rejected, "main.go:12:9", "bpf.Array.AtomicAdd is an eBPF-side operation"},
	{"ebpf_calls_user_method", GB003CrossDomainUse, Rejected, "main.go:8:9", "bpf.Array.Get is a user-space operation"},
	{"user_calls_program", GB003CrossDomainUse, Rejected, "main.go:12:2", "cannot be called from user space"},
	{"program_as_value", GB004UnknownEdge, Unknown, "main.go:12:7", "is used as a value"},
	{"reserved_name", GB007ReservedName, Rejected, "main.go:7:5", `"gobpf_mine" uses the prefix "gobpf_"`},
	{"nonconst_maxentries", GB006NonConstant, Rejected, "main.go:7:52", "MaxEntries must be a constant"},
	{"program_shape", GB008ProgramShape, Rejected, "main.go:7:6", "is not a program"},
	{"subprogram_call", GB013SubprogramShape, Rejected, "main.go:7:6", "must return exactly one integer or bool"},
	{"generated_ref", GB000TypeCheck, Rejected, "main.go:12:6", "undefined: gobpf_elf"},
	{"reassign_checked", GB005NilCheckShape, Rejected, "main.go:9:3", "the checked pointer p must not be reassigned"},
	// Integer rules and the single exit
	{"shift_width", GB012IntegerRule, Rejected, "main.go:7:39", "shift count 32 is outside [0, 32) for i32"},
	{"shift_variable", GB012IntegerRule, Rejected, "main.go:7:42", "shift count must be a constant"},
	{"div_variable", GB012IntegerRule, Rejected, "main.go:7:41", "the divisor must be a non-zero constant"},
	{"div_minus_one", GB012IntegerRule, Rejected, "main.go:7:36", "a signed division by the constant -1 is rejected"},
	{"float_type", GB011CapabilityNotProvided, Rejected, "main.go:8:7", `needs capability "go.float"`},
	{"return_in_branch", GB001UnsupportedConstruct, Rejected, "main.go:9:3", "one exit"},
	// RequirementSet and the subprogram boundary
	{"chain3_fmt", GB011CapabilityNotProvided, Rejected, "main.go:12:2", `C needs capability "go.runtime" (call to fmt.Println)`},
	{"chain_unknown", GB011CapabilityNotProvided, Unknown, "main.go:9:2", `B needs capability "unknown"`},
	{"recursion_direct", GB010Recursion, Rejected, "main.go:7:34", "recursion among eBPF-side functions"},
	{"recursion_mutual", GB010Recursion, Rejected, "main.go:9:34", "recursion among eBPF-side functions"},
	{"sub_six_args", GB013SubprogramShape, Rejected, "main.go:7:6", "has 6 parameters; at most 5"},
	{"sub_multi_result", GB013SubprogramShape, Rejected, "main.go:7:6", "must return exactly one integer or bool"},
	// sub_pointer_param (passing a checked borrow) became an accepted shape — the negative case is now a pointer that is not a map value (sa_ptr_nonmap)
	{"sa_ptr_nonmap", GB013SubprogramShape, Rejected, "main.go:12:6", "a pointer to something other than a map value"},
	// sa_write, sa_atomic, wp_write_ptr (writes to a borrow argument) became accepted shapes (callee_write_test.go) — the negative cases are shared-map RMW (cw_*)
	{"sa_mixed", GB013SubprogramShape, Rejected, "main.go:8:6", "subprogram get is called with a checked map value for p (main.go:14:11, main.go:17:12) and with an unchecked M.Lookup(k) (main.go:19:22)"},
	{"sa_maybe_unchecked", GB005NilCheckShape, Rejected, "main.go:9:39", "use of p outside `if p != nil { … }` — callers pass M.Lookup(k) unchecked"},
	{"sa_borrowed_nilcheck", GB013SubprogramShape, Rejected, "main.go:11:5", "p is never nil in subprogram safe"},
	{"sa_bad_arg", GB013SubprogramShape, Rejected, "main.go:11:43", "the pointer argument of get must be a checked map value"},
	{"sa_two_ptrs", GB013SubprogramShape, Rejected, "main.go:9:6", "subprogram add has more than one pointer parameter"},
	{"sa_global_on_prog", GB013SubprogramShape, Rejected, "main.go:9:1", "//gobpf:global marks a subprogram (a helper called from a program) — Prog is a program"},
	{"sa_global_not_sub", GB013SubprogramShape, Rejected, "main.go:14:1", "//gobpf:global marks an eBPF-side subprogram — helper is not one"},
	{"sa_rmw_ref", GB028NonAtomicRMW, Rejected, "main.go:17:3", "p.A is written from a value read from itself (through the return value of readA)"},
	// Writes to a callee's borrow argument — a non-atomic RMW of a shared map value is GB028 / GB021 at the call site (the callee summary), a same-record
	// delta inside the callee is the lowerer's GB021, and `*c = v` on an integer value and lock record arguments still stop.
	// A (W) variable key across functions — the frontend cannot show the keys differ, so it stops (bpf-mlir's rmwprobe does not compare across SSA keys).
	{"rmwx_arg_varkey", GB028NonAtomicRMW, Rejected, "main.go:32:6", "writeK(…) writes its argument 2 to R[k & 3].N (writeK: p.N = …), and the argument reads R[k].N (through the local variable x) here"},
	{"cw_inc", GB028NonAtomicRMW, Rejected, "main.go:20:7", "bump(…) does p.N++ (main.go:14:2) through its pointer parameter p, and here it is passed a value of the shared map R (key 0)"},
	{"cw_add_assign", GB028NonAtomicRMW, Rejected, "main.go:20:7", "add(…) does p.N += … (main.go:14:2) through its pointer parameter p, and here it is passed a value of the shared map H (key 3)"},
	{"cw_self_local", GB028NonAtomicRMW, Rejected, "main.go:21:7", "inc(…) does p.N = …p.N… (through the local variable n) (main.go:15:2) through its pointer parameter p"},
	{"cw_maybe_inc", GB028NonAtomicRMW, Rejected, "main.go:23:6", "bump(…) does p.N++ (main.go:16:3) through its pointer parameter p, and here it is passed a value of the shared map R (key 2)"},
	{"cw_win_rmw", GB028NonAtomicRMW, Rejected, "main.go:25:8", "count(…) does p.Hits++ (main.go:16:3) through its pointer parameter p, and here it is passed a value of the shared map Rules (key 0)"},
	{"cw_caller_read", GB028NonAtomicRMW, Rejected, "main.go:21:7", "set(…) writes its argument 2 to R[0].N (set: p.N = …), and the argument reads R[0].N (through the local variable x) here"},
	{"cw_atomic_arg", GB021AtomicShape, Rejected, "main.go:20:7", "addN(…) writes its argument 2 to R[0].N (addN: bpf.AtomicAdd(&p.N, …)), and the argument reads R[0].M here — an atomic add whose delta reads the same value"},
	{"cw_atomic_self", GB021AtomicShape, Rejected, "main.go:14:22", "the delta of bpf.AtomicAdd reads a field of the same record (p.M)"},
	{"cw_atomic_local", GB021AtomicShape, Rejected, "main.go:15:22", "the delta of bpf.AtomicAdd reads a field of the same record through the local variable d"},
	{"cw_int_star", GB001UnsupportedConstruct, Unknown, "main.go:9:2", "assignment target must be a local variable"},
	// A global (bpf.Global) G.Add whose delta carries a Load of the same global — silently generated up to v0.12.0, now GB021.
	{"ga_direct", GB021AtomicShape, Rejected, "main.go:9:8", "the delta of G.Add reads the same global G — the read and the add are not one atomic step"},
	{"ga_local", GB021AtomicShape, Rejected, "main.go:10:8", "the delta of G.Add reads the same global G (through the local variable v)"},
	{"ga_helper_w", GB021AtomicShape, Rejected, "main.go:14:6", "bump(…) adds its argument 1 to the global G (bump: G.Add(…)), and the argument reads G here"},
	{"ga_helper_r", GB021AtomicShape, Rejected, "main.go:13:8", "the delta of G.Add reads the same global G (through the return value of get)"},
	{"cw_lock_rec", GB013SubprogramShape, Rejected, "main.go:14:6", "subprogram setN parameter p: a pointer to something other than a map value"},
	// Packet windows
	{"win_index_out", GB014WindowIndex, Rejected, "main.go:10:19", "outside the checked window of 14 bytes"},
	{"win_index_var", GB006NonConstant, Rejected, "main.go:11:19", "the index of w.U8 must be a constant"},
	{"win_len_var", GB006NonConstant, Rejected, "main.go:10:27", "the length of ctx.Check must be a constant"},
	{"win_cond_not_ok", GB005NilCheckShape, Rejected, "main.go:9:32", "the condition must be exactly `ok`"},
	{"win_in_else", GB005NilCheckShape, Rejected, "main.go:12:14", "use of w here is not allowed"},
	{"win_user_side", GB003CrossDomainUse, Rejected, "main.go:13:11", "bpf.XDPContext.Check is an eBPF-side operation"},
	{"win_escape", GB001UnsupportedConstruct, Unknown, "main.go:8:6", "has type github.com/yuskesh/go-bpf-mlir/bpf.Window"},
	// eBPF-side functions referenced as values on the user side
	{"user_callback_bpf", GB004UnknownEdge, Unknown, "main.go:17:11", "the eBPF-side function G is used as a value"},
	{"user_var_bpf", GB004UnknownEdge, Unknown, "main.go:15:7", "the eBPF-side function G is used as a value"},
	{"pkgvar_bpf", GB004UnknownEdge, Unknown, "main.go:14:12", "the eBPF-side function G is used as a value"},
	// uintptr is outside the type table
	{"uintptr_local", GB001UnsupportedConstruct, Unknown, "main.go:8:6", "variable x has type uintptr"},
	{"uintptr_param", GB013SubprogramShape, Rejected, "main.go:7:6", "uintptr cannot be passed to a subprogram"},
	// eBPF-side shapes of records
	{"rec_whole_deref", GB016SharedABIShape, Rejected, "main.go:14:3", "variable x holds the record Seen"},
	{"rec_atomic_add", GB016SharedABIShape, Rejected, "main.go:13:2", "M.AtomicAdd needs an integer value, but M holds the record Seen"},
	{"rec_var_index", GB006NonConstant, Rejected, "main.go:15:10", "the index of p.Hist must be a constant"},
	{"rec_value_var", GB011CapabilityNotProvided, Rejected, "main.go:13:7", `needs capability "go.heap"`},
	{"rec_positional", GB001UnsupportedConstruct, Unknown, "main.go:13:19", "a record literal must name its fields"},
	{"rec_field_in_else", GB005NilCheckShape, Rejected, "main.go:17:7", "use of p outside the checked branch"},
	{"rec_array_whole", GB011CapabilityNotProvided, Rejected, "main.go:14:12", `needs capability "go.heap"`},
	// User stacks and kprobe pointer arguments: existing codes keep their meaning (no new code needed — the frozen table goes up to GB027)
	{"us_xdp", GB000TypeCheck, Rejected, "main.go:12:20", "does not implement bpf.StackContext"},
	{"us_kernelid_buildid", GB000TypeCheck, Rejected, "main.go:13:13", "Builds.KernelID undefined (type bpf.StackBuildID has no field or method KernelID)"},
	{"us_ptr_local", GB001UnsupportedConstruct, Unknown, "main.go:13:2", "variable p has type uintptr"},
	{"us_ptr_narrow", GB008ProgramShape, Rejected, "main.go:13:23", "bpf.KprobeArg[uintptr] is the raw 8-byte pointer value — convert it to uint64 or int64"},
	{"us_ptr_conflict", GB008ProgramShape, Rejected, "main.go:14:23", "argument 1 of the kprobe program onPoll is read as a pointer at main.go:13:23 and as uint32 here"},
	{"us_ptr_uprobe", GB000TypeCheck, Rejected, "main.go:13:37", "uintptr does not satisfy bpf.KprobeInt"},
	{"us_status_ignored", GB017StatusIgnored, Rejected, "main.go:13:2", "the raw status of Stacks.UserID is discarded"},
	{"us_in_loop", GB018LoopShape, Rejected, "main.go:14:7", "Stacks.UserID cannot be inside a loop"},
	// Rules for call paths inside loops (R1 reaching the ring buffer, R2 path depth and product) — the agreement test is callloop_test.go
	{"cl_ring_direct", GB018LoopShape, Rejected, "main.go:16:7", "emit is called inside a loop and reaches the ring buffer (Prog → loop 4 → emit → Events.Output)"},
	{"cl_ring_twolevel", GB018LoopShape, Rejected, "main.go:18:7", "relay is called inside a loop and reaches the ring buffer (Prog → loop 4 → relay → emit → Events.Output)"},
	{"cl_ring_callee_loop", GB018LoopShape, Rejected, "main.go:17:6", "emit is called inside a loop and reaches the ring buffer (burst → loop 4 → emit → Events.Output)"},
	{"cl_depth3", GB018LoopShape, Rejected, "main.go:25:8", "loops nest 3 deep along Prog → loop 2 → inner → loop 2 → loop 2 — at most 2"},
	{"cl_depth3_callee", GB018LoopShape, Rejected, "main.go:25:8", "loops nest 3 deep along mid → loop 2 → leaf → loop 2 → loop 2 — at most 2"},
	{"cl_product72", GB018LoopShape, Rejected, "main.go:23:8", "the loop counts along Prog → loop 8 → inner → loop 9 multiply to 72 — at most 64"},
	{"cl_product_twolevel", GB018LoopShape, Rejected, "main.go:25:8", "the loop counts along Prog → loop 4 → mid → leaf → loop 32 multiply to 128 — at most 64"},
	// Non-atomic RMW of shared maps (GB028 — a new code) and same-value deltas of integer-map AtomicAdd (extends GB021). Accepted shapes are in rmw_test.go
	{"rmw_field_plus", GB028NonAtomicRMW, Rejected, "main.go:16:3", "s.N += … is a non-atomic read-modify-write of a value in the shared map R"},
	{"rmw_incdec", GB028NonAtomicRMW, Rejected, "main.go:16:3", "p.N++ is a non-atomic read-modify-write of a value in the shared map R"},
	{"rmw_int_star", GB028NonAtomicRMW, Rejected, "main.go:16:3", "*p += … is a non-atomic read-modify-write of a value in the shared map C"},
	{"rmw_local", GB028NonAtomicRMW, Rejected, "main.go:17:3", "p.N is written from a value read from itself (through the local variable x)"},
	{"rmw_merge", GB028NonAtomicRMW, Rejected, "main.go:19:3", "p.N is written from a value read from itself (through the local variable x)"},
	{"rmw_loop", GB028NonAtomicRMW, Rejected, "main.go:20:3", "p.N is written from a value read from itself (through the local variable m)"},
	{"rmw_update_same_key", GB028NonAtomicRMW, Rejected, "main.go:16:3", "C.Update(0, …) writes back a value read from C (key 0) — the keys are not shown to differ"},
	{"rmw_update_var_key", GB028NonAtomicRMW, Rejected, "main.go:14:3", "C.Update(k, …) writes back a value read from C (key k) — the keys are not shown to differ"},
	{"rmw_update_unknown_key", GB028NonAtomicRMW, Rejected, "main.go:14:3", "C.Update(k, …) writes back a value read from C (key 0) — the keys are not shown to differ"},
	{"rmw_update_record", GB028NonAtomicRMW, Rejected, "main.go:16:3", "R.Update(1, …) writes back a value read from R (key 1)"},
	{"rmw_cb_conflict", GB028NonAtomicRMW, Rejected, "main.go:15:2", "w.Fired is a non-atomic read-modify-write in the timer callback onFire, and a program also writes w.Fired of map Wins (main.go:25:3)"},
	{"rmw_cb_conflict", GB028NonAtomicRMW, Rejected, "main.go:25:3", "w.Fired writes a field of map Wins that the timer callback onFire updates non-atomically (main.go:15:2)"},
	{"rmw_atomic_int_direct", GB021AtomicShape, Rejected, "main.go:16:18", "the delta of C.AtomicAdd reads a value of the same map C (key 0) — the keys are not shown to differ"},
	{"rmw_atomic_int_local", GB021AtomicShape, Rejected, "main.go:19:17", "the delta of C.AtomicAdd reads a value of the same map C (key 0) (through the local variable d)"},
	// Origins across subprograms — carried by return value (R), by argument (W), transitively. The mutation controls are in rmw_test.go
	{"rmwx_ret_field", GB028NonAtomicRMW, Rejected, "main.go:24:3", "p.N is written from a value read from itself (through the return value of readN)"},
	{"rmwx_ret_update", GB028NonAtomicRMW, Rejected, "main.go:17:2", "C.Update(0, …) writes back a value read from C (key 0) (through the return value of readC)"},
	{"rmwx_ret_atomic", GB021AtomicShape, Rejected, "main.go:17:17", "the delta of C.AtomicAdd reads a value of the same map C (key 0) (through the return value of readC)"},
	{"rmwx_arg_field", GB028NonAtomicRMW, Rejected, "main.go:27:6", "writeN(…) writes its argument 1 to R[0].N (writeN: p.N = …), and the argument reads R[0].N (through the local variable x) here"},
	{"rmwx_arg_update", GB028NonAtomicRMW, Rejected, "main.go:18:6", "putC(…) writes its argument 1 to C[0] (putC: C.Update(0, …)), and the argument reads C[0] (through the local variable y) here"},
	{"rmwx_arg_atomic", GB021AtomicShape, Rejected, "main.go:18:6", "addC(…) writes its argument 1 to C[0] (addC: C.AtomicAdd(0, …)), and the argument reads C[0] (through the local variable y) here — an atomic add"},
	// The "before" of the migration examples in the v0.4.0 release notes (the "after" is the accepted shape in rmw_test.go)
	{"mig1_before", GB028NonAtomicRMW, Rejected, "main.go:14:3", "p.Packets += … is a non-atomic read-modify-write of a value in the shared map Counts"},
	{"mig2_before", GB028NonAtomicRMW, Rejected, "main.go:19:3", "p.Packets++ is a non-atomic read-modify-write of a value in the shared map PerProto"},
	{"mig3_before", GB028NonAtomicRMW, Rejected, "main.go:10:3", "C.Update(0, …) writes back a value read from C (key 0)"},
	{"rmwx_transitive", GB028NonAtomicRMW, Rejected, "main.go:27:6", "store(…) writes its argument 1 to C[0] (store → putC: C.Update(0, …)), and the argument reads C[0] (through the return value of relay → readC) here"},
	// Map MaxEntries limit (bpf-mlir's K9 — the size of the BTF int[MaxEntries] fits in u32)
	{"map_k9", GB009MapDeclShape, Rejected, "main.go:5:46", "map M: MaxEntries 1073741824 is over the limit 1073741823"},
	{"rb_k9", GB009MapDeclShape, Rejected, "main.go:9:42", "map Events: MaxEntries 1073741824 is over the limit 1073741823"},
	// Nested records: limits (depth, dimensions), shapes outside (anonymous, nested lock), whole copies, unproven indexes, AtomicAdd on a variable path
	{"nest_depth4", GB016SharedABIShape, Rejected, "main.go:18:6", "record L4 nests records 4 deep — at most 3"},
	{"nest_3d", GB016SharedABIShape, Rejected, "main.go:11:2", "field C has 3 array dimensions — at most 2"},
	{"nest_rec2d", GB016SharedABIShape, Rejected, "main.go:11:2", "field G is a 2-dimensional array of records — an array of records has one dimension"},
	{"nest_anon", GB016SharedABIShape, Rejected, "main.go:11:2", "field A holds an anonymous struct — a nested record is a named struct type"},
	{"nest_lock_inner", GB016SharedABIShape, Rejected, "main.go:16:2", "a record with a lock or timer cannot be nested in another record"},
	{"nest_whole_assign", GB016SharedABIShape, Rejected, "main.go:19:3", "p.A is the nested record Pt — a whole record is not a value"},
	{"nest_elem_whole", GB016SharedABIShape, Rejected, "main.go:19:3", "p.Pts[1] is the nested record Pt — a whole record is not a value"},
	{"nest_whole_var", GB016SharedABIShape, Rejected, "main.go:18:3", "variable x holds the record Pt"},
	{"nest_unchecked", GB006NonConstant, Rejected, "main.go:20:9", "the index of p.Pts must be a constant, or a uint32 variable checked by"},
	{"nest_else_index", GB006NonConstant, Rejected, "main.go:23:10", "the index of p.Pts must be a constant"},
	{"nest_atomic_var", GB021AtomicShape, Rejected, "main.go:21:25", "bpf.AtomicAdd needs a constant field path — the index of p.Pts is not a constant"},
	{"nest_guard_assign", GB014WindowIndex, Rejected, "main.go:21:4", "the checked index i must not be assigned inside the range check"},
	{"nest_literal_positional", GB001UnsupportedConstruct, Unknown, "main.go:17:22", "a record literal must name its fields (Pt{F: e, …})"},
	// Ring buffer
	{"rb_size_var", GB006NonConstant, Rejected, "main.go:13:45", "MaxEntries must be a constant"},
	{"rb_size_pow2", GB009MapDeclShape, Rejected, "main.go:11:45", "must be a power of two and a multiple of the x86_64 page size (4096), got 5000"},
	{"rb_size_small", GB009MapDeclShape, Rejected, "main.go:11:45", "got 2048"},
	{"wa_global", GB013SubprogramShape, Rejected, "main.go:10:6", "global subprogram proto takes a packet window — only a static subprogram can"},
	{"wa_len_mismatch", GB013SubprogramShape, Rejected, "main.go:8:6", "subprogram etype is called with packet windows of different lengths (14 at main.go:18:13; 24 at main.go:15:13)"},
	{"wa_forward", GB013SubprogramShape, Rejected, "main.go:13:15", "subprogram outer passes its packet window w on to inner"},
	{"wa_tc_write", GB013SubprogramShape, Rejected, "main.go:23:12", "subprogram mark writes the packet through its window w (main.go:9:2), but sched_cls program Q calls it"},
	{"wa_two_windows", GB013SubprogramShape, Rejected, "main.go:8:6", "subprogram both has more than one packet window parameter"},
	{"wa_index_out", GB014WindowIndex, Rejected, "main.go:9:21", "w.U8(23) reads bytes [23, 23+1) outside the checked window of 14 bytes"},
	{"wa_else_branch", GB005NilCheckShape, Rejected, "main.go:17:13", "use of w here is not allowed: the packet is shorter than the checked range in the else branch"},
	{"wa_stale", GB025PacketWrite, Rejected, "main.go:16:14", "window w was checked before ctx.AdjustHead at main.go:15:12"},
	{"rb_event_too_big", GB009MapDeclShape, Rejected, "main.go:11:45", "event Event is 4088 bytes (4096 with the 8-byte header, rounded up to 8), but a ring of 4096 bytes can reserve at most 4080 bytes per event"},
	{"rb_event_over_ring", GB009MapDeclShape, Rejected, "main.go:11:45", "raise MaxEntries to 16384 or shrink the event"},
	{"rb_int_event", GB016SharedABIShape, Rejected, "main.go:11:5", "the event type must be a record"},
	{"rb_drop_key_out", GB009MapDeclShape, Rejected, "main.go:14:55", "the key 2 of bpf.CountDropsIn is outside map Drops (MaxEntries 2)"},
	{"rb_drop_key_var", GB006NonConstant, Rejected, "main.go:15:55", "the key of bpf.CountDropsIn must be a constant"},
	{"rb_event_var", GB016SharedABIShape, Rejected, "main.go:14:6", "variable e holds the record Event"},
	{"rb_user_output", GB003CrossDomainUse, Rejected, "main.go:18:9", "bpf.RingBuf.Output is an eBPF-side operation"},
	{"rb_user_addr", GB009MapDeclShape, Rejected, "main.go:17:8", "map variable Events may only be used as the receiver of its methods"}, // the address only as an argument of gobpf.NewReader
	{"rb_output_ignored", GB017StatusIgnored, Rejected, "main.go:12:2", "the result of Events.Output (whether the event was submitted) is discarded and no drop counter is given"},
	// fexit directive nargs and the return value type
	{"fexit_no_nargs", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fexit needs the number of arguments of the kernel function as `nargs=<0..12>`"},
	{"fexit_nargs_13", GB008ProgramShape, Rejected, "main.go:7:1", "12 is the kernel's MAX_BPF_FUNC_ARGS"},
	{"fexit_nargs_name", GB008ProgramShape, Rejected, "main.go:7:1", "`nargs=<0..12>` (a literal"},
	{"fexit_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the fexit program f needs the kernel function to attach to — write `//gobpf:fexit <function> nargs=<N>`"},
	{"fentry_with_nargs", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fentry takes only the kernel function name"},
	{"fexit_bool_ret", GB000TypeCheck, Rejected, "main.go:8:30", "bool does not satisfy ~int8 | ~int16 | ~int32 | ~int64"},
	{"fexit_wrong_kind", GB008ProgramShape, Rejected, "main.go:7:1", "directive //gobpf:fentry is not supported (the fexit program f takes //gobpf:fexit <kernel function> nargs=<N>)"},
	// fentry directives and CurrentComm
	{"fentry_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the fentry program f needs the kernel function to attach to"},
	{"fentry_two_directives", GB008ProgramShape, Rejected, "main.go:8:1", "the fentry program f has 2 //gobpf:fentry directives"},
	{"fentry_bad_name", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fentry \"do-sys-poll\" is not a kernel function name"},
	{"fentry_other_kind", GB008ProgramShape, Rejected, "main.go:7:1", "directive //gobpf:fexit is not supported"},
	{"fentry_directive_on_xdp", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fentry is only allowed right above a fentry program"},
	{"fentry_directive_on_var", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fentry is only allowed right above a fentry program"},
	{"fentry_with_result", GB008ProgramShape, Rejected, "main.go:8:6", "a fentry program func(ctx *bpf.FentryContext) with no result"},
	{"fentry_comm_outside", GB001UnsupportedConstruct, Rejected, "main.go:9:6", "bpf.CurrentComm() may only be the value of a [16]uint8 field in a ring buffer event literal"},
	// bpf.AtomicAdd (GB021 AtomicShape)
	{"atomic_elem", GB021AtomicShape, Rejected, "main.go:18:18", "bpf.AtomicAdd cannot add to an array element"},
	{"atomic_local", GB021AtomicShape, Rejected, "main.go:18:17", "the operand of & is not a field of a checked record pointer"},
	{"atomic_int_map", GB021AtomicShape, Rejected, "main.go:18:17", "p points to the integer value of a map — add to it with the map's own method"},
	{"atomic_16bit", GB000TypeCheck, Rejected, "main.go:18:3", "uint16 does not satisfy ~uint32 | ~uint64 | ~int32 | ~int64"}, // Go's type constraint stops the width
	{"atomic_addr_outside", GB011CapabilityNotProvided, Rejected, "main.go:18:8", "taking an address (&)"},                    // & only in the first argument of bpf.AtomicAdd
	{"atomic_user", GB003CrossDomainUse, Rejected, "main.go:22:6", "bpf.AtomicAdd is an eBPF-side operation"},
	{"atomic_same_ref", GB021AtomicShape, Rejected, "main.go:14:23", "the delta of bpf.AtomicAdd reads a field of the same record (p.G)"},
	// Global variables
	{"global_ebpf_set", GB003CrossDomainUse, Rejected, "main.go:8:8", "bpf.Config.Set is a user-space operation"},
	{"global_user_add", GB003CrossDomainUse, Rejected, "main.go:13:4", "bpf.Global.Add is an eBPF-side operation"},
	{"global_config_add", GB000TypeCheck, Rejected, "main.go:8:4", "A.Add undefined (type bpf.Config[uint32] has no field or method Add)"}, // Go's types stop writes to .rodata
	{"global_16bit", GB000TypeCheck, Rejected, "main.go:5:20", "uint16 does not satisfy bpf.GlobalInt"},
	{"global_optional_var", GB006NonConstant, Rejected, "main.go:7:38", "global A: Optional must be a constant"},
	{"global_copy", GB009MapDeclShape, Rejected, "main.go:14:8", "global variable A may only be used as the receiver of its methods"},
	// A delta carrying a field of the same borrow through a local variable
	{"atomic_delta_local", GB021AtomicShape, Rejected, "main.go:16:23", "reads a field of the same record through the local variable v"},
	{"atomic_delta_arith", GB021AtomicShape, Rejected, "main.go:16:23", "reads a field of the same record through the local variable v"},
	{"atomic_delta_merge", GB021AtomicShape, Rejected, "main.go:19:23", "reads a field of the same record through the local variable v"},
	{"atomic_delta_chain", GB021AtomicShape, Rejected, "main.go:17:23", "reads a field of the same record through the local variable b"},
	// lpm_trie
	{"lpm_ebpf_put", GB003CrossDomainUse, Rejected, "main.go:12:8", "bpf.LPMTrie4.Put is a user-space operation"},
	{"lpm_user_lookup", GB003CrossDomainUse, Rejected, "main.go:16:11", "bpf.LPMTrie4.Lookup is an eBPF-side operation"},
	{"lpm_value16", GB000TypeCheck, Rejected, "main.go:5:22", "uint16 does not satisfy bpf.LPMValue"},
	{"lpm_update", GB000TypeCheck, Rejected, "main.go:8:4", "has no field or method Update"}, // lpm_trie is read-only inside a program (Go's types stop it)
	{"lpm_no_max", GB009MapDeclShape, Rejected, "main.go:5:9", "map T: MaxEntries is required"},
	{"lpm_discarded", GB005NilCheckShape, Rejected, "main.go:8:2", "the result of T.Lookup is discarded"},
	{"lpm_addr_var", GB011CapabilityNotProvided, Rejected, "main.go:9:7", `needs capability "go.heap"`}, // the address only of a `[4]byte{…}` Lookup argument
	{"lpm_record_prefix", GB007ReservedName, Rejected, "main.go:5:6", `uses the prefix "gobpf_" reserved`},
	// Zero-value shapes (stop with a position instead of panicking. Accepted shapes: zero_int8, uint64, bool, action, int)
	{"zero_ptr", GB005NilCheckShape, Rejected, "main.go:8:6", "variable x holds a pointer to a map value (*uint64) — the result of M.Lookup(k) may be nil and is read only inside `if x := M.Lookup(k); x != nil { … }`"}, // from GB001 to GB005, which says how to fix it
	{"zero_array", GB001UnsupportedConstruct, Unknown, "main.go:8:6", "variable x has type [4]byte, which is not in the supported subset"},
	{"zero_struct", GB001UnsupportedConstruct, Unknown, "main.go:12:6", "which is not in the supported subset (integers and bool)"},
	{"zero_string", GB011CapabilityNotProvided, Rejected, "main.go:9:6", `needs capability "go.string"`},
	{"zero_float", GB011CapabilityNotProvided, Rejected, "main.go:9:23", `needs capability "go.float"`},
	// Shapes outside the conditional verdict
	{"verdict_nonconst", GB006NonConstant, Rejected, "main.go:14:10", "the returned action must be a constant (bpf.XDPPass, …) — to choose it by a condition"},
	{"verdict_extra_stmt", GB001UnsupportedConstruct, Rejected, "main.go:14:3", "return is only supported as the last statement"},
	{"verdict_else_if", GB001UnsupportedConstruct, Rejected, "main.go:13:3", "return is only supported as the last statement"},
	{"verdict_not_last", GB001UnsupportedConstruct, Rejected, "main.go:13:3", "return is only supported as the last statement"},
	{"verdict_in_check", GB001UnsupportedConstruct, Rejected, "main.go:14:4", "or as the only statement of an arm of the body's final `if c { return A }; return B`"},
	{"verdict_bad_action", GB001UnsupportedConstruct, Rejected, "main.go:13:10", "action 7 is not a supported xdp verdict (aborted / drop / pass / tx)"},
	// kprobe
	{"kprobe_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the kprobe program f needs the kernel function to attach to"},
	{"kprobe_x64_alias", GB008ProgramShape, Rejected, "main.go:7:1", "write the kernel function itself, not its \"__x64_\" syscall wrapper alias"},
	{"kprobe_arg_nonconst", GB008ProgramShape, Rejected, "main.go:10:50", "the argument number of bpf.KprobeArg must be a constant 1..6"},
	{"kprobe_arg_range", GB008ProgramShape, Rejected, "main.go:9:50", "the argument number of bpf.KprobeArg must be a constant 1..6"},
	{"kprobe_arg_zero", GB008ProgramShape, Rejected, "main.go:9:50", "the argument number of bpf.KprobeArg must be a constant 1..6"},
	{"kprobe_arg_two_types", GB008ProgramShape, Rejected, "main.go:10:7", "argument 2 of the kprobe program f is read as int32 here but as uint32 at main.go:9:7"},
	{"kprobe_arg_user", GB003CrossDomainUse, Rejected, "main.go:13:13", "bpf.KprobeArg is an eBPF-side operation"},
	{"kprobe_extra", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:kprobe takes only the kernel function name"},
	// tracepoint, raw_tp, kretprobe, uretprobe
	{"trh_tag_array", GB008ProgramShape, Rejected, "main.go:9:2", "the tagged field Fork.Comm has type [16]byte — a tracepoint field read is an 8 / 16 / 32 / 64-bit integer"},
	{"trh_tag_offset", GB008ProgramShape, Rejected, "main.go:8:2", "the tagged field Enter.Nr is at offset 0 — the first 8 bytes of a tracepoint record are the common fields"},
	{"trh_tag_dup", GB008ProgramShape, Rejected, "main.go:10:2", "the tracefs field \"ret\" is tagged twice in Exit"},
	{"trh_no_tag", GB008ProgramShape, Rejected, "main.go:14:6", "the event type Exit has no field tagged `tp:\"<name>\"`"},
	{"trh_event_not_struct", GB008ProgramShape, Rejected, "main.go:8:6", "the event type uint64 in *bpf.TracepointContext[E] must be a named struct type"},
	{"trh_event_value", GB008ProgramShape, Rejected, "main.go:15:2", "variable e holds ctx.Event() — the event record is not a value"},
	{"trh_event_store", GB001UnsupportedConstruct, Unknown, "main.go:15:2", "assignment target must be a local variable"},
	{"trh_untagged", GB008ProgramShape, Rejected, "main.go:15:35", "Exit.Ret has no `tp:\"<name>\"` tag"},
	{"trh_tp_noslash", GB008ProgramShape, Rejected, "main.go:12:1", "//gobpf:tracepoint takes one tracefs event as `<category>/<event>`"},
	{"trh_rawtp_nonconst", GB008ProgramShape, Rejected, "main.go:10:34", "the argument index of bpf.RawTPArg must be a constant 0..11"},
	{"trh_rawtp_range", GB008ProgramShape, Rejected, "main.go:9:34", "the argument index of bpf.RawTPArg must be a constant 0..11"},
	{"trh_ret_8bit", GB000TypeCheck, Rejected, "main.go:8:34", "int8 does not satisfy bpf.RetInt"},
	{"trh_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the kretprobe program f needs its attach point — write `//gobpf:kretprobe <kernel function>`"},
	{"trh_uret_bad_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:uretprobe takes the binary's path"},
	{"trh_uret_go", GB008ProgramShape, Rejected, "main.go:7:1", "uretprobe program f: cgofix.bin: uprobe target main.goSum is not a SysV (C ABI) function"},
	{"trh_with_result", GB008ProgramShape, Rejected, "main.go:8:6", "f takes a program context but is not a program"},
	// socket and cgroup
	{"skc_field_hook", GB008ProgramShape, Rejected, "main.go:9:23", "the cgroup_sock field type cannot be read in a cgroup_sock program at the sock_release hook"},
	{"skc_ip4_inet6", GB008ProgramShape, Rejected, "main.go:7:2", "the cgroup_sock_addr field user_ip4 cannot be written in a cgroup_sock_addr program at the connect6 hook"},
	{"skc_allow_only", GB008ProgramShape, Rejected, "main.go:7:9", "the cgroup_sock_addr hook getsockname4 only allows bpf.CgroupAllow"},
	{"skc_hook_bad", GB008ProgramShape, Rejected, "main.go:5:1", "//gobpf:cgroup_sock_addr takes one hook name"},
	{"skc_hook_extra", GB008ProgramShape, Rejected, "main.go:5:1", "//gobpf:cgroup_sock_addr takes one hook name"},
	{"skc_hook_missing", GB008ProgramShape, Rejected, "main.go:5:6", "the cgroup_sock program f needs its attach point — write `//gobpf:cgroup_sock <sock_create|sock_release|post_bind4|post_bind6>`"},
	{"skc_sf_cgroup_action", GB008ProgramShape, Rejected, "main.go:5:6", "f takes a program context but is not a program"},
	{"skc_egress_cn", GB001UnsupportedConstruct, Rejected, "main.go:6:9", "action 3 is not a supported cgroup_skb verdict (deny / allow)"},
	{"skc_read_discard", GB008ProgramShape, Rejected, "main.go:6:2", "the value of ctx.Op is discarded"},
	{"skc_sf_check", GB000TypeCheck, Rejected, "main.go:6:18", "ctx.Check undefined (type *bpf.SocketFilterContext has no field or method Check)"},
	{"skc_sub_ctx", GB013SubprogramShape, Rejected, "main.go:7:6", "the cgroup_sock_addr context cannot be passed to a subprogram"},
	{"skc_user_side", GB003CrossDomainUse, Rejected, "main.go:11:8", "bpf.SocketFilterContext.Len is an eBPF-side operation"},
	// Reads through kprobe pointer arguments
	{"kr_off_var", GB008ProgramShape, Rejected, "main.go:10:42", "the offset of bpf.KprobeRead must be a constant 0..4095"},
	{"kr_off_4096", GB008ProgramShape, Rejected, "main.go:9:42", "the offset of bpf.KprobeRead must be a constant 0..4095"},
	{"kr_off_neg", GB008ProgramShape, Rejected, "main.go:9:42", "the offset of bpf.KprobeRead must be a constant 0..4095"},
	{"kr_n_zero", GB008ProgramShape, Rejected, "main.go:9:39", "the argument number of bpf.KprobeRead must be a constant 1..6"},
	{"kr_type_bool", GB000TypeCheck, Rejected, "main.go:9:26", "uintptr does not satisfy bpf.KprobeInt"},
	{"kr_discard", GB017StatusIgnored, Rejected, "main.go:7:2", "the value and the raw status of bpf.KprobeRead are discarded"},
	{"kr_in_if", GB008ProgramShape, Rejected, "main.go:10:3", "bpf.KprobeRead must be a top-level statement of the kprobe program body"},
	{"kr_in_loop", GB008ProgramShape, Rejected, "main.go:10:3", "bpf.KprobeRead must be a top-level statement of the kprobe program body"},
	{"kr_sub", GB013SubprogramShape, Rejected, "main.go:8:11", "bpf.KprobeRead reads an attach-specific value, which a subprogram that takes the context cannot do"},
	{"kr_int_conflict", GB008ProgramShape, Rejected, "main.go:10:11", "argument 3 of the kprobe program f is read through as a pointer here but as int32 at main.go:9:7"},
	{"kr_uprobe", GB000TypeCheck, Rejected, "main.go:9:34", "cannot use ctx (variable of type *bpf.UprobeContext) as *bpf.KprobeContext value in argument to bpf.KprobeRead[uint64]"},
	// fentry integer arguments
	{"fi_idx_var", GB027KernelTypeShape, Rejected, "main.go:10:37", "the argument index of bpf.FentryArgInt must be a constant 0..11"},
	{"fi_idx_12", GB027KernelTypeShape, Rejected, "main.go:9:37", "the argument index of bpf.FentryArgInt must be a constant 0..11"},
	{"fi_in_if", GB027KernelTypeShape, Rejected, "main.go:10:3", "bpf.FentryArgInt must be a top-level statement of the fentry program body"},
	{"fi_expr", GB027KernelTypeShape, Rejected, "main.go:9:16", "bpf.FentryArgInt must be a top-level statement of the fentry program body"},
	{"fi_type_uintptr", GB000TypeCheck, Rejected, "main.go:9:24", "uintptr does not satisfy bpf.KprobeInt"},
	{"fi_dup", GB027KernelTypeShape, Rejected, "main.go:15:10", "argument 0 of the fentry program f is read as sock here but as i64 at main.go:14:7"},
	{"fi_sub", GB027KernelTypeShape, Rejected, "main.go:8:7", "bpf.FentryArgInt may only be used in the body of a fentry program"},
	{"fi_tp_btf", GB000TypeCheck, Rejected, "main.go:9:31", "cannot use ctx (variable of type *bpf.TPBTFContext) as *bpf.FentryContext value in argument to bpf.FentryArgInt[uint8]"},
	// lsm and lsm.s
	{"lsm_deny_zero", GB001UnsupportedConstruct, Rejected, "main.go:9:21", "the errno of bpf.LSMDeny must be 1..4095 (got 0"},
	{"lsm_deny_4096", GB001UnsupportedConstruct, Rejected, "main.go:10:22", "the errno of bpf.LSMDeny must be 1..4095 (got 4096"},
	{"lsm_deny_var", GB006NonConstant, Rejected, "main.go:10:21", "the errno of bpf.LSMDeny must be a constant 1..4095"},
	{"lsm_ret_conv", GB006NonConstant, Rejected, "main.go:10:9", "the returned value of the lsm program must be a constant"},
	{"lsm_ret_range", GB001UnsupportedConstruct, Rejected, "main.go:9:9", "the lsm program returns 1, outside -4095..0"},
	{"lsm_no_result", GB008ProgramShape, Rejected, "main.go:8:6", "f takes a program context but is not a program"},
	{"lsm_arg_nocheck", GB005NilCheckShape, Rejected, "main.go:14:7", "bpf.LSMArg returns a pointer that may be NULL"},
	{"lsm_argint_in_if", GB027KernelTypeShape, Rejected, "main.go:10:3", "bpf.LSMArgInt must be a top-level statement of the lsm program body"},
	{"lsm_argint_12", GB027KernelTypeShape, Rejected, "main.go:9:35", "the argument index of bpf.LSMArgInt must be a constant 0..11"},
	{"lsm_kind_mismatch", GB008ProgramShape, Rejected, "main.go:7:1", "directive //gobpf:lsm_s is not supported (the lsm program f takes //gobpf:lsm <LSM hook>)"},
	{"lsm_arg_fentry", GB000TypeCheck, Rejected, "main.go:9:7", "bpf.FentryContext does not satisfy bpf.LSMHook"},
	{"lsm_no_hook", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:lsm takes one LSM hook name without the bpf_lsm_ prefix"},
	{"lsm_deny_expr", GB001UnsupportedConstruct, Rejected, "main.go:9:7", "bpf.LSMDeny may only be the returned value of a lsm program"},
	// perf_event
	{"pe_with_result", GB008ProgramShape, Rejected, "main.go:7:6", "onSample takes a program context but is not a program"},
	{"pe_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:perf_event is only allowed right above a fentry program"},
	{"pe_other_ctx", GB008ProgramShape, Rejected, "main.go:10:16", "ctx.SamplePeriod must be called on the program's context parameter"},
	{"pe_sub", GB013SubprogramShape, Rejected, "main.go:7:6", "the perf_event context cannot be passed to a subprogram"},
	{"pe_in_loop", GB018LoopShape, Rejected, "main.go:10:8", "ctx.SamplePeriod cannot be read inside a loop"},
	{"pe_in_kprobe", GB008ProgramShape, Rejected, "main.go:11:16", "ctx.SamplePeriod may only be called in the body of a perf_event program"},
	// Keyless maps
	{"kl_push_discard", GB017StatusIgnored, Rejected, "main.go:8:2", "the status of Q.Push is discarded"},
	{"kl_pop_discard", GB017StatusIgnored, Rejected, "main.go:8:2", "the value and the raw status of Q.Pop are discarded"},
	{"kl_in_loop", GB018LoopShape, Rejected, "main.go:13:11", "S.Pop cannot be called inside a loop"},
	{"kl_flag_var", GB006NonConstant, Rejected, "main.go:15:18", "the flag of Q.Push must be the constant bpf.PushAny or bpf.PushExist"},
	{"kl_user_take", GB003CrossDomainUse, Rejected, "main.go:11:12", "bpf.Queue.Take is a user-space operation"},
	{"kl_record_value", GB000TypeCheck, Rejected, "main.go:9:19", "Ev does not satisfy bpf.KprobeInt"},
	// map-in-map
	{"mim_outer_update", GB000TypeCheck, Rejected, "main.go:8:4", "A.Update undefined"},
	{"mim_escape", GB005NilCheckShape, Rejected, "main.go:9:8", "the inner map m of A may only be used as the receiver"},
	{"mim_in_loop", GB018LoopShape, Rejected, "main.go:10:4", "the inner map m of A cannot be used inside a loop"},
	{"mim_sub", GB005NilCheckShape, Rejected, "main.go:14:12", "the inner map m of A may only be used as the receiver"},
	{"mim_nocheck", GB005NilCheckShape, Rejected, "main.go:8:7", "A.Lookup returns an inner map that may be absent"},
	{"mim_kind_var", GB006NonConstant, Rejected, "main.go:7:83", "Inner.Kind must be the constant bpf.InnerArray, bpf.InnerHash or bpf.InnerLRUHash"},
	{"mim_no_inner", GB009MapDeclShape, Rejected, "main.go:5:9", "map A: Inner is required"},
	// XDP redirect maps
	{"xr_not_last", GB008ProgramShape, Rejected, "main.go:8:2", "X.Redirect is a terminator"},
	{"xr_fallback_var", GB006NonConstant, Rejected, "main.go:12:28", "the fallback action of C.Redirect must be a constant xdp verdict"},
	{"xr_tcx", GB000TypeCheck, Rejected, "main.go:8:20", "cannot use ctx (variable of type *bpf.TCIngressContext) as *bpf.XDPContext value in argument to X.Redirect"},
	{"xr_set_ebpf", GB003CrossDomainUse, Rejected, "main.go:8:8", "bpf.DevMapHash.Set is a user-space operation"},
	{"xr_no_max", GB009MapDeclShape, Rejected, "main.go:5:9", "map C: MaxEntries is required"},
	// ksyscall
	{"ks_n0", GB008ProgramShape, Rejected, "main.go:9:36", "the argument number of bpf.KsyscallArg must be a constant 1..6"},
	{"ks_n7", GB008ProgramShape, Rejected, "main.go:9:36", "the argument number of bpf.KsyscallArg must be a constant 1..6"},
	{"ks_nvar", GB008ProgramShape, Rejected, "main.go:10:36", "the argument number of bpf.KsyscallArg must be a constant 1..6"},
	{"ks_in_if", GB008ProgramShape, Rejected, "main.go:10:3", "bpf.KsyscallArg must be a top-level statement of the ksyscall program body"},
	{"ks_kprobe", GB000TypeCheck, Rejected, "main.go:9:31", "cannot use ctx (variable of type *bpf.KprobeContext) as *bpf.KsyscallContext value"},
	{"ks_no_name", GB008ProgramShape, Rejected, "main.go:7:6", "the ksyscall program f needs its attach point"},
	{"ks_wrapper_name", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:ksyscall takes one syscall name without the wrapper prefix"},
	// kprobe_multi / kretprobe_multi
	{"km_empty", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:kprobe_multi needs at least one kernel function"},
	{"km_dup", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:kprobe_multi lists vfs_read twice"},
	{"km_glob", GB008ProgramShape, Rejected, "main.go:7:1", "a glob is not supported"},
	{"km_alias", GB008ProgramShape, Rejected, "main.go:7:1", "write the kernel function itself, not its \"__x64_\" syscall wrapper alias"},
	{"km_index_single", GB008ProgramShape, Rejected, "main.go:9:16", "bpf.ProbeTargetIndex may only be called in the body of a multi probe program"},
	{"km_with_result", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:kprobe_multi is only allowed right above"},
	// uprobe_multi / uretprobe_multi (testdata's umfix is a symlink to the umulti difftest fixture umfix)
	{"um_empty", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:uprobe_multi needs at least one symbol"},
	{"um_dup", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:uprobe_multi lists um_add twice"},
	{"um_glob", GB008ProgramShape, Rejected, "main.go:7:1", "a glob is not supported — list the symbols by name"},
	{"um_no_symbol", GB008ProgramShape, Rejected, "main.go:7:1", "the binary has 0 FUNC symbols named no_such_function"},
	{"um_wide_type", GB008ProgramShape, Rejected, "main.go:11:23", "uprobe_multi program f reads argument 1 of um_wide as i64, but it is i32 in the binary's DWARF"},
	{"um_str", GB008ProgramShape, Rejected, "main.go:14:31", "not in a uprobe_multi program, which reads integer arguments only"},
	// usdt (testdata's usfix is a symlink to the usdt difftest fixture usfix — note points: three us:hit, one us:guarded)
	{"us_no_point", GB008ProgramShape, Rejected, "main.go:7:1", "usdt program f: usfix has no USDT point us:missing"},
	{"us_bad_target", GB008ProgramShape, Rejected, "main.go:7:1", "the USDT point as `<provider>:<name>`"},
	{"us_too_many", GB008ProgramShape, Rejected, "main.go:9:10", "reads argument 3 of us:hit, but the point at pc 0x1190 has 2 arguments"},
	{"us_wrong_type", GB008ProgramShape, Rejected, "main.go:11:10", "reads argument 1 of us:guarded as int32, but the point at pc 0x11ee describes it as \"-2@-10(%rsp)\" (int16)"},
	{"us_nonconst", GB008ProgramShape, Rejected, "main.go:10:35", "the argument number of bpf.USDTArg must be a constant 1..12"},
	{"us_n13", GB008ProgramShape, Rejected, "main.go:9:35", "the argument number of bpf.USDTArg must be a constant 1..12"},
	{"us_callee", GB013SubprogramShape, Rejected, "main.go:7:6", "the usdt context cannot be passed to a subprogram"},
	// sockmap, sockhash and sk_skb
	{"sm_lookup", GB000TypeCheck, Rejected, "main.go:9:11", "Socks.Lookup undefined (type bpf.SockMap has no field or method Lookup)"},
	{"sm_redirect_assign", GB005NilCheckShape, Rejected, "main.go:9:7", "Socks's methods are statements"},
	{"sm_redirect_nested", GB001UnsupportedConstruct, Rejected, "main.go:10:3", "return is only supported as the last statement"},
	{"sm_dir_array", GB008ProgramShape, Rejected, "main.go:7:1", "Stat is a array map — a sk_skb program attaches to a bpf.SockMap or bpf.SockHash"},
	{"sm_dir_missing", GB008ProgramShape, Rejected, "main.go:7:1", "no bpf.SockMap / bpf.SockHash variable named Nope in this package"},
	{"sm_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the sk_skb program f needs its attach point — write `//gobpf:sk_skb <sockmap or sockhash variable>`"},
	{"sm_redirect_callee", GB008ProgramShape, Rejected, "main.go:7:6", "the sk_skb program pick needs its attach point"},
	{"sm_hash_record_key", GB000TypeCheck, Rejected, "main.go:9:25", "K does not satisfy bpf.KprobeInt"},
	// The back-edge loop directive
	{"lpb_u_estimate", GB018LoopShape, Rejected, "main.go:9:2", "unrolling a body estimated at 133 op(s) (+4 per copy) 64 times is estimated at more than 4096 op(s)"},
	{"lpb_not_for", GB008ProgramShape, Rejected, "main.go:8:2", "//gobpf:loop must be on the line right above a for statement"},
	{"lpb_mode", GB008ProgramShape, Rejected, "main.go:8:2", "the loop mode must be backedge or callback"},
	{"lpb_twice", GB008ProgramShape, Rejected, "main.go:9:35", "//gobpf:loop must be on the line right above a for statement"},
	{"lpb_check", GB018LoopShape, Rejected, "main.go:11:15", "ctx.Check cannot be inside a `//gobpf:loop backedge` loop"},
	// cgroup_array
	{"cga_skbxdp", GB008ProgramShape, Rejected, "main.go:13:5", "CG.SkbUnder asks about the skb's socket — it may only be called in the body of a tc program"},
	{"cga_skbctx", GB008ProgramShape, Rejected, "main.go:11:17", "the first argument of CG.SkbUnder must be the program's context parameter"},
	{"cga_notcg", GB000TypeCheck, Rejected, "main.go:11:8", "A.TaskUnder undefined (type bpf.Array[uint32, uint64] has no field or method TaskUnder)"},
	// user_ringbuf
	{"urb_mapcall", GB026LockTimerShape, Rejected, "main.go:17:2", "the drain callback onMsg: only bpf.Global Add calls may be statements"},
	{"urb_loop", GB018LoopShape, Rejected, "main.go:23:7", "In.Drain cannot be called inside a loop"},
	{"urb_sig", GB026LockTimerShape, Rejected, "main.go:16:6", "the drain callback onMsg must be `func onMsg(r V, ok bool) bool`"},
	{"urb_subprog", GB008ProgramShape, Rejected, "main.go:22:9", "In.Drain may only be called in a program body"},
	{"urb_branch", GB026LockTimerShape, Rejected, "main.go:18:3", "the drain callback onMsg: only bpf.Global Add calls may be inside an if"},
	// struct_ops arguments and kfield.store
	{"sops_argidx", GB027KernelTypeShape, Rejected, "main.go:21:11", "argument 1 of the tcp_congestion_ops member cong_avoid is a u32 integer"},
	{"sops_argint", GB027KernelTypeShape, Rejected, "main.go:19:11", "the type argument of bpf.StructOpsArgInt must be uint32, got i64"},
	{"sops_store_nonso", GB027KernelTypeShape, Rejected, "main.go:14:3", "the kernel struct field p.Prio cannot be written — kernel pointers are read-only"},
	{"sops_store_nil", GB005NilCheckShape, Rejected, "main.go:21:2", "bpf.StructOpsArg returns a pointer that may be NULL"},
	// struct_ops (tcp_congestion_ops)
	{"sops_noundo", GB009MapDeclShape, Rejected, "main.go:6:5", "tcp_congestion_ops needs the members ssthresh, undo_cwnd and cong_avoid — missing [undo_cwnd]"},
	{"sops_member", GB008ProgramShape, Rejected, "main.go:17:1", "go supports the tcp_congestion_ops members init, ssthresh, undo_cwnd and cong_avoid only"},
	{"sops_ret", GB008ProgramShape, Rejected, "main.go:8:1", "the member ssthresh returns uint32 in tcp_congestion_ops — ss has (uint64)"},
	{"sops_dup", GB009MapDeclShape, Rejected, "main.go:6:5", "the member ssthresh is implemented twice (ss and ss2)"},
	{"sops_twomaps", GB009MapDeclShape, Rejected, "main.go:8:2", "this package already declares the struct_ops map CC"},
	{"sops_name", GB009MapDeclShape, Rejected, "main.go:6:37", "must be 1 to 15 characters of [A-Za-z0-9_.]"},
	// ext (freplace)
	{"ext_static", GB008ProgramShape, Rejected, "main.go:15:1", "g is not marked //gobpf:global — the kernel replaces only global functions"},
	{"ext_notcalled", GB008ProgramShape, Rejected, "main.go:21:1", "program tgt does not call g"},
	{"ext_noprog", GB008ProgramShape, Rejected, "main.go:17:1", "someone_elses_prog is not a program of this package"},
	{"ext_argtype", GB008ProgramShape, Rejected, "main.go:19:16", "bpf.ExtArg[int32](ctx, 0): argument 0 of g is uint32 — the type argument must be identical"},
	{"ext_rettype", GB008ProgramShape, Rejected, "main.go:17:1", "the ext program rep returns uint64 but g returns uint32"},
	{"ext_ptrarg", GB008ProgramShape, Rejected, "main.go:22:1", "g must take at most 5 integer arguments and return one integer"},
	// syscall
	{"sys_align", GB008ProgramShape, Rejected, "main.go:7:53", "the offset of bpf.SyscallLoad[i32] must be a multiple of 4"},
	{"sys_toofar", GB008ProgramShape, Rejected, "main.go:7:53", "the offset of bpf.SyscallLoad[i64] must be a multiple of 8 with offset + 8 ≤ 65535 (got 65528"},
	{"sys_nonconst", GB006NonConstant, Rejected, "main.go:8:53", "the offset of bpf.SyscallLoad must be a constant"},
	{"sys_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the syscall context cannot be passed to a subprogram"},
	// kprobe_session
	{"ksess_range", GB001UnsupportedConstruct, Rejected, "main.go:9:9", "the kprobe_session program returns 2, outside 0..1"},
	{"ksess_computed", GB006NonConstant, Rejected, "main.go:15:9", "the returned value of the kprobe_session program must be a constant"},
	{"ksess_loop", GB018LoopShape, Rejected, "main.go:12:17", "ctx.Cookie cannot be called inside a loop"},
	{"ksess_twofuncs", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:kprobe_session takes only the kernel function name"},
	// raw_tp_writable
	{"rawtpw_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the raw_tp_writable context cannot be passed to a subprogram"},
	{"rawtpw_valtype", GB000TypeCheck, Rejected, "main.go:12:17", "cannot use *v (variable of type uint64) as int32 value in argument to ctx.SetBuffer"},
	{"rawtpw_nodirective", GB008ProgramShape, Rejected, "main.go:6:6", "the raw_tp_writable program onFinish needs its attach point"},
	{"rawtpw_otherctx", GB000TypeCheck, Rejected, "main.go:9:10", "ctx.Buffer undefined (type *bpf.RawTPContext has no field or method Buffer)"},
	{"rawtpw_loop", GB018LoopShape, Rejected, "main.go:12:31", "ctx.Buffer cannot be called inside a loop"},
	// fmod_ret
	{"fmodret_rettype", GB000TypeCheck, Rejected, "main.go:9:9", "cannot use bpf.LSMAllow (constant 0 of int32 type bpf.LSMRet) as bpf.FmodRet value"},
	{"fmodret_nargs", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:fmod_ret needs the number of arguments of the kernel function as `nargs=<0..12>`"},
	{"fmodret_ptrarg", GB000TypeCheck, Rejected, "main.go:9:25", "*int32 does not satisfy bpf.KprobeInt"},
	{"fmodret_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the fmod_ret context cannot be passed to a subprogram"},
	{"fmodret_select", GB001UnsupportedConstruct, Rejected, "main.go:13:22", "are both evaluated before the choice"},
	// lwt_seg6local
	{"seg6_verdict", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.LWTOK (constant 0 of uint32 type bpf.LWTAction) as bpf.Seg6Action value"},
	{"seg6_check", GB000TypeCheck, Rejected, "main.go:7:18", "ctx.Check undefined (type *bpf.Seg6LocalContext has no field or method Check)"},
	{"seg6_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the lwt_seg6local context cannot be passed to a subprogram"},
	{"seg6_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:lwt_seg6local is only allowed right above"},
	// lwt_in / lwt_out / lwt_xmit
	{"lwt_winwrite", GB025PacketWrite, Rejected, "main.go:8:3", "writes the packet of a lwt_xmit program"},
	{"lwt_verdict", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.XDPPass (constant 2 of uint32 type bpf.XDPAction) as bpf.LWTAction value"},
	{"lwt_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the lwt_out context cannot be passed to a subprogram"},
	{"lwt_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:lwt_out is only allowed right above"},
	// netfilter
	{"nf_verdict", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.XDPPass (constant 2 of uint32 type bpf.XDPAction) as bpf.NFAction value"},
	{"nf_field", GB000TypeCheck, Rejected, "main.go:7:9", "ctx.Mark undefined (type *bpf.NetfilterContext has no field or method Mark)"},
	{"nf_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the netfilter context cannot be passed to a subprogram"},
	{"nf_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:netfilter is only allowed right above"},
	// flow_dissector
	{"fd_subprog", GB013SubprogramShape, Rejected, "main.go:6:6", "the flow_dissector context cannot be passed to a subprogram"},
	{"fd_winwrite", GB025PacketWrite, Rejected, "main.go:8:3", "writes the packet of a flow_dissector program"},
	{"fd_verdict", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.CgroupAllow (constant 1 of int32 type bpf.CgroupAction) as bpf.FlowAction value"},
	{"fd_width", GB000TypeCheck, Rejected, "main.go:8:17", "cannot use p (variable of type uint16) as uint8 value"},
	// sk_reuseport and reuseport_sockarray
	{"rp_loop", GB018LoopShape, Rejected, "main.go:11:12", "Socks.Select cannot be called inside a loop"},
	{"rp_otherctx", GB000TypeCheck, Rejected, "main.go:10:15", "cannot use ctx (variable of type *bpf.SkLookupContext) as *bpf.SkReuseportContext value"},
	{"rp_lookup", GB000TypeCheck, Rejected, "main.go:10:16", "Socks.Lookup undefined (type bpf.ReuseportSockArray has no field or method Lookup)"},
	{"rp_write", GB000TypeCheck, Rejected, "main.go:7:6", "ctx.SetHash undefined (type *bpf.SkReuseportContext has no field or method SetHash)"},
	// sk_lookup
	{"skl_write", GB000TypeCheck, Rejected, "main.go:7:6", "ctx.SetLocalPort undefined (type *bpf.SkLookupContext has no field or method SetLocalPort)"},
	{"skl_verdict", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.CgroupAllow (constant 1 of int32 type bpf.CgroupAction) as bpf.SKAction value"},
	{"skl_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:sk_lookup is only allowed right above"},
	{"skl_port32", GB000TypeCheck, Rejected, "main.go:7:17", "cannot use ctx.RemotePort() (value of type uint16) as uint32 value"},
	// cgroup_sockopt
	{"sockopt_loop", GB018LoopShape, Rejected, "main.go:9:4", "writes the optval of a cgroup_sockopt program inside a loop"},
	{"sockopt_subprog", GB013SubprogramShape, Rejected, "main.go:13:7", "but cgroup_sockopt program onSet calls it — packet writes are xdp-only"},
	{"sockopt_skbwrite", GB025PacketWrite, Rejected, "main.go:8:3", "writes the packet of a cgroup_skb program"},
	{"sockopt_setlevel", GB000TypeCheck, Rejected, "main.go:7:6", "ctx.SetLevel undefined (type *bpf.CgroupSetsockoptContext has no field or method SetLevel)"},
	{"sockopt_index", GB014WindowIndex, Rejected, "main.go:8:13", "outside the checked window of 4 bytes"},
	// cgroup_sysctl
	{"sysctl_var", GB011CapabilityNotProvided, Rejected, "main.go:7:7", `needs capability "go.string" (value of type string)`},
	{"sysctl_empty", GB008ProgramShape, Rejected, "main.go:7:18", "the value of ctx.SetNewValue must be 1 to 64 bytes (got 0"},
	{"sysctl_long", GB008ProgramShape, Rejected, "main.go:9:18", "the value of ctx.SetNewValue must be 1 to 64 bytes (got 65"},
	{"sysctl_loop", GB018LoopShape, Rejected, "main.go:8:3", "ctx.SetNewValue cannot be called inside a loop"},
	{"sysctl_other", GB000TypeCheck, Rejected, "main.go:7:6", "ctx.SetNewValue undefined (type *bpf.CgroupDeviceContext has no field or method SetNewValue)"},
	// cgroup_device
	{"cgdev_write", GB000TypeCheck, Rejected, "main.go:7:6", "ctx.SetMajor undefined (type *bpf.CgroupDeviceContext has no field or method SetMajor)"},
	{"cgdev_lsmret", GB000TypeCheck, Rejected, "main.go:7:9", "cannot use bpf.LSMAllow (constant 0 of int32 type bpf.LSMRet) as bpf.CgroupAction value"},
	{"cgdev_directive", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:cgroup_device is only allowed right above"},
	// iter (bpf_map_elem only)
	{"iter_target", GB008ProgramShape, Rejected, "main.go:9:1", "bpf_map_elem is the only target go supports"},
	{"iter_no_map", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:iter takes the iterator target and the map to iterate"},
	{"iter_ringbuf", GB008ProgramShape, Rejected, "main.go:13:1", "Events is a ringbuf map — a bpf_map_elem iterator iterates an array or a hash map"},
	{"iter_write_int", GB008ProgramShape, Rejected, "main.go:12:15", "SeqFile.Write takes a record value"},
	{"iter_seq_bare", GB005NilCheckShape, Rejected, "main.go:15:6", "SeqFile.Write needs the checked pointer of `if s := ctx.Seq(); s != nil { … }`"},
	{"iter_result", GB008ProgramShape, Rejected, "main.go:10:6", "an iter program func(ctx *bpf.IterContext) with no result"},
	// fsession (added with the cilium fork)
	{"fsess_cookie_u32", GB000TypeCheck, Rejected, "main.go:10:16", "cannot use v (variable of type uint32) as uint64 value in argument to ctx.SetCookie"},
	{"fsess_no_func", GB008ProgramShape, Rejected, "main.go:6:6", "the fsession program f needs the kernel function to attach to"},
	{"fsess_fentry_ctx", GB000TypeCheck, Rejected, "main.go:11:9", "ctx.IsReturn undefined (type *bpf.FentryContext has no field or method IsReturn)"},
	{"fsess_in_loop", GB018LoopShape, Rejected, "main.go:12:20", "ctx.Cookie cannot be called inside a loop"},
	{"fsess_result", GB008ProgramShape, Rejected, "main.go:8:6", "a fsession program func(ctx *bpf.FsessionContext) with no result"},
	// lsm_cgroup (restored with the cilium fork)
	{"lsmcg_arg", GB000TypeCheck, Rejected, "main.go:11:23", "bpf.LSMCgroupContext does not satisfy bpf.LSMHook"},
	{"lsmcg_lsmret", GB000TypeCheck, Rejected, "main.go:9:9", "cannot use bpf.LSMAllow (constant 0 of int32 type bpf.LSMRet) as bpf.CgroupAction value"},
	{"lsmcg_no_hook", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:lsm_cgroup takes one LSM hook name without the bpf_lsm_ prefix"},
	{"lsmcg_prefix", GB008ProgramShape, Rejected, "main.go:7:1", "//gobpf:lsm_cgroup takes one LSM hook name without the bpf_lsm_ prefix"},
	// The context in callback loop bodies
	{"lpc_ctx", GB018LoopShape, Rejected, "main.go:11:6", "the context cannot be used inside a `//gobpf:loop callback` loop"},
	{"lpc_ctx_call", GB018LoopShape, Rejected, "main.go:15:31", "the context cannot be used inside a `//gobpf:loop callback` loop"},
	{"lpc_check", GB018LoopShape, Rejected, "main.go:11:15", "the context cannot be used inside a `//gobpf:loop callback` loop"},
	{"lpc_nested_ctx", GB018LoopShape, Rejected, "main.go:12:7", "the context cannot be used inside a `//gobpf:loop callback` loop"},
	// Go shape rules for ring buffer reservations (the number of consumes is bpf-mlir's ownership — TestReserveOwnershipLocs)
	{"rsv_not_init", GB005NilCheckShape, Rejected, "main.go:13:11", "Events.Reserve may only be the init of an if statement"},
	{"rsv_cond", GB005NilCheckShape, Rejected, "main.go:14:32", "the condition must be exactly `ok`"},
	{"rsv_read_field", GB005NilCheckShape, Rejected, "main.go:15:9", "a reserved event cannot be read or passed on"},
	{"rsv_read_star", GB005NilCheckShape, Rejected, "main.go:17:18", "a reserved event cannot be read or passed on"},
	{"rsv_copy", GB005NilCheckShape, Rejected, "main.go:14:8", "a reserved event cannot be read or passed on"},
	{"rsv_pass", GB005NilCheckShape, Rejected, "main.go:18:8", "a reserved event cannot be read or passed on"},
	{"rsv_else", GB005NilCheckShape, Rejected, "main.go:16:18", "e is not reserved in the else branch"},
	{"rsv_loop", GB018LoopShape, Rejected, "main.go:14:15", "Events.Reserve cannot be inside a loop"},
	// sched_act (test run only)
	{"act_bad_verdict", GB001UnsupportedConstruct, Rejected, "main.go:7:9", "action 7 is not a supported sched_act verdict (ok / shot / pipe)"},
	{"act_mark_read", GB000TypeCheck, Rejected, "main.go:9:27", "ctx.Mark undefined (type *bpf.TCActContext has no field or method Mark)"},
	{"act_callee", GB013SubprogramShape, Rejected, "main.go:7:6", "the sched_act context cannot be passed to a subprogram"},
	{"act_two_ifs", GB001UnsupportedConstruct, Rejected, "main.go:7:3", "return is only supported as the last statement"},
	// sk_msg and sock_ops Insert
	{"mg_redirect_nested", GB001UnsupportedConstruct, Rejected, "main.go:10:3", "return is only supported as the last statement"},
	{"mg_insert_callee", GB013SubprogramShape, Rejected, "main.go:10:6", "the sock_ops context cannot be passed to a subprogram"},
	{"mg_insert_flags_var", GB006NonConstant, Rejected, "main.go:15:29", "the flags of Socks.Insert must be the constant bpf.SockAny, bpf.SockNoExist or bpf.SockExist"},
	{"mg_insert_loop", GB018LoopShape, Rejected, "main.go:12:9", "Socks.Insert cannot be called inside a loop"},
	{"mg_insert_discard", GB017StatusIgnored, Rejected, "main.go:8:2", "the status of Socks.Insert is discarded"},
	{"mg_dir_array", GB008ProgramShape, Rejected, "main.go:7:1", "Stat is a array map — a sk_msg program attaches to a bpf.SockMap or bpf.SockHash"},
	{"mg_no_directive", GB008ProgramShape, Rejected, "main.go:7:6", "the sk_msg program f needs its attach point"},
	{"sm_set_in_ebpf", GB003CrossDomainUse, Rejected, "main.go:9:8", "bpf.SockMap.Set is a user-space operation and cannot be used on the eBPF side"},
	// Local storage maps
	{"stg_owner_kind", GB027KernelTypeShape, Rejected, "main.go:15:21", "the owner of Tasks.Get is a pointer to the kernel struct sock (Sock), but a task_storage map is keyed by task_struct"},
	{"stg_owner_int", GB027KernelTypeShape, Rejected, "main.go:10:20", "the owner of Tasks.Get must be a checked kernel pointer variable"},
	{"stg_owner_unchecked", GB027KernelTypeShape, Rejected, "main.go:14:20", "the owner of Socks.Get must be a checked kernel pointer variable"},
	{"stg_delete_discard", GB017StatusIgnored, Rejected, "main.go:15:3", "the status of Socks.Delete is discarded"},
	{"stg_flag_var", GB006NonConstant, Rejected, "main.go:16:24", "the second argument of Socks.Get must be the constant bpf.Create or bpf.NoCreate"},
	{"stg_get_value", GB005NilCheckShape, Rejected, "main.go:15:3", "Socks.Get may only be used as `if v := Socks.Get(owner, bpf.Create); v != nil { … }`"},
	{"stg_in_loop", GB008ProgramShape, Rejected, "main.go:16:12", "Socks.Get may not be called inside a loop"},
	{"stg_lookup", GB000TypeCheck, Rejected, "main.go:9:16", "Tasks.Lookup undefined"},
	{"stg_max_entries", GB000TypeCheck, Rejected, "main.go:5:37", "unknown field MaxEntries in struct literal of type bpf.TaskStorage[uint64]"},
	{"stg_user_get", GB003CrossDomainUse, Rejected, "main.go:8:12", "bpf.TaskStorage.Get is an eBPF-side operation"},
	{"stg_value_narrow", GB009MapDeclShape, Rejected, "main.go:5:5", "map Tasks: an integer value must be 32 or 64 bit, got uint16"},
	// devmap and redirect_map
	{"redir_not_last", GB008ProgramShape, Rejected, "main.go:8:2", "Ports.Redirect is a terminator — write it as the program's last statement"},
	{"redir_fallback_var", GB006NonConstant, Rejected, "main.go:9:32", "the fallback action of Ports.Redirect must be a constant xdp verdict"},
	{"redir_otherwise_var", GB006NonConstant, Rejected, "main.go:9:53", "the otherwise action of Ports.RedirectIf must be a constant xdp verdict"},
	{"redir_fallback_redirect", GB006NonConstant, Rejected, "main.go:8:32", "not a redirect"},
	{"redir_user", GB003CrossDomainUse, Rejected, "main.go:11:39", "bpf.DevMap.Redirect is an eBPF-side operation"},
	{"redir_ebpf_set", GB003CrossDomainUse, Rejected, "main.go:8:12", "bpf.DevMap.Set is a user-space operation"},
	{"redir_lookup", GB000TypeCheck, Rejected, "main.go:8:16", "has no field or method Lookup"},
	{"redir_no_max", GB009MapDeclShape, Rejected, "main.go:7:13", "map Other: MaxEntries is required"},
	{"redir_mixed", GB001UnsupportedConstruct, Rejected, "main.go:15:3", "return is only supported as the last statement"}, // mixing a conditional verdict and a redirect is not accepted
	// uprobe
	{"uprobe_go_func", GB008ProgramShape, Rejected, "main.go:14:1", "uprobe target main.goSum is not a SysV (C ABI) function: its compilation unit is Go (DW_AT_language 0x16"},
	{"uprobe_no_file", GB008ProgramShape, Rejected, "main.go:14:1", "cannot open the target binary nosuchbin"},
	{"uprobe_abs_path", GB008ProgramShape, Rejected, "main.go:14:1", "must be relative to the package directory and inside it"},
	{"uprobe_no_symbol", GB008ProgramShape, Rejected, "main.go:14:1", "the binary has 0 FUNC symbols named no_such_function"},
	{"uprobe_wrong_type", GB008ProgramShape, Rejected, "main.go:16:23", "reads argument 2 of sum_args as i16, but it is u32 in the binary's DWARF"},
	{"uprobe_str_not_char", GB008ProgramShape, Rejected, "main.go:18:37", "reads argument 1 of sum_args as strptr, but it is i64"},
	{"uprobe_status_missing", GB016SharedABIShape, Rejected, "main.go:15:9", "Names.OutputStr needs exactly one int64 field tagged `gobpf:\"userstr_status\"` in the event record Ev, found 0 — the kernel zero-fills the string when the read fails"},
	{"uprobe_status_two", GB016SharedABIShape, Rejected, "main.go:18:9", "needs exactly one int64 field tagged `gobpf:\"userstr_status\"` in the event record Ev, found 2"},
	{"uprobe_status_int32", GB016SharedABIShape, Rejected, "main.go:16:9", "the `gobpf:\"userstr_status\"` field Status of Ev must be int64"},
	{"uprobe_status_in_literal", GB016SharedABIShape, Rejected, "main.go:17:36", "the `gobpf:\"userstr_status\"` field Status is written by OutputStr — leave it out of the event literal"},
	{"uprobe_str_elsewhere", GB001UnsupportedConstruct, Unknown, "main.go:16:2", "variable s has type github.com/yuskesh/go-bpf-mlir/bpf.UserStr, which is not in the supported subset"},
	{"uprobe_status_discarded", GB017StatusIgnored, Rejected, "main.go:16:2", "the status of Names.OutputStr (the raw probe_read_user_str status)"},
	{"uprobe_bad_directive", GB008ProgramShape, Rejected, "main.go:14:1", "//gobpf:uprobe takes the binary's path"},
	{"uprobe_arg_str_conflict", GB008ProgramShape, Rejected, "main.go:16:16", "reads argument 1 of greet as u64, but it is strptr"},
	{"uprobe_user_side", GB003CrossDomainUse, Rejected, "main.go:19:29", "bpf.UprobeArg is an eBPF-side operation"},
	// eBPF-side function names starting with `__ebpf_` are reserved for the compiler (bpf-mlir's outlining uses __ebpf_present_<function>_<n>).
	{"rn_subprogram", GB013SubprogramShape, Rejected, "main.go:8:6", "the eBPF-side function name __ebpf_present_Prog_0 starts with __ebpf_, which is reserved for functions the compiler adds"},
	{"rn_program", GB013SubprogramShape, Rejected, "main.go:8:6", "the eBPF-side function name __ebpf_count starts with __ebpf_, which is reserved"},
	// OutputStrOrDiscard inherits OutputStr's rules (no status field is needed — at most one if present).
	{"od_status_discarded", GB017StatusIgnored, Rejected, "main.go:16:2", "the status of Names.OutputStrOrDiscard (the raw probe_read_user_str status) and whether it was submitted are discarded"},
	{"od_in_loop", GB018LoopShape, Rejected, "main.go:20:12", "Names.OutputStrOrDiscard cannot be inside a loop"},
	{"od_no_userstr", GB016SharedABIShape, Rejected, "main.go:18:11", "Names.OutputStrOrDiscard needs exactly one field tagged `gobpf:\"userstr\"` in the event record Ev, found 0"},
	{"od_status_two", GB016SharedABIShape, Rejected, "main.go:20:11", "Names.OutputStrOrDiscard takes at most one int64 field tagged `gobpf:\"userstr_status\"` in the event record Ev, found 2"},
	{"od_userstr_in_literal", GB016SharedABIShape, Rejected, "main.go:18:47", "the `gobpf:\"userstr\"` field Name is written by OutputStrOrDiscard — leave it out of the event literal"},
	{"uprobe_no_userstr_field", GB016SharedABIShape, Rejected, "main.go:14:9", "needs exactly one field tagged `gobpf:\"userstr\"` in the event record Ev, found 0"},
	// A stale window after AdjustHead on the right of a short circuit (merging packet generations)
	{"sc_adjust_window", GB025PacketWrite, Rejected, "main.go:11:15", "window w was checked before ctx.AdjustHead at main.go:10:17"},
	// Stack traces and perf events (fentry only — Go's types stop other contexts)
	{"sp_not_fentry", GB000TypeCheck, Rejected, "main.go:10:32", "cannot use ctx (variable of type *bpf.KprobeContext) as *bpf.FentryContext value"},
	{"sp_skip_nonconst", GB006NonConstant, Rejected, "main.go:11:37", "the skip of Stacks.KernelID must be a constant (0 to 255)"},
	{"sp_skip_range", GB009MapDeclShape, Rejected, "main.go:10:42", "the skip 256 of Stacks.KernelIDReuse is outside 0 to 255"},
	{"sp_status_discarded", GB017StatusIgnored, Rejected, "main.go:9:2", "the raw status of Stacks.KernelID is discarded"},
	{"perf_status_discarded", GB017StatusIgnored, Rejected, "main.go:14:2", "the raw status of Events.Output is discarded"},
	{"sp_in_loop", GB018LoopShape, Rejected, "main.go:11:17", "Stacks.KernelID cannot be inside a loop"},
	{"sp_user_side", GB003CrossDomainUse, Rejected, "main.go:13:17", "bpf.StackTrace.KernelID is an eBPF-side operation"},
	{"sp_depth_zero", GB009MapDeclShape, Rejected, "main.go:5:52", "stack trace map Stacks: Depth must be a positive constant"},
	{"sp_depth_missing", GB009MapDeclShape, Rejected, "main.go:5:14", "stack trace map Stacks: Depth is required"},
	{"sp_lookup", GB000TypeCheck, Rejected, "main.go:9:17", "type bpf.StackTrace has no field or method Lookup"},
	{"perf_not_record", GB016SharedABIShape, Rejected, "main.go:5:5", "perf event array Events: the event type must be a record"},
	// Spin locks and timers (escapes from the region: return is GB026, break is Go's types, goto / defer / panic hit the capability check (GB011) first)
	{"lock_call_in_region", GB026LockTimerShape, Rejected, "main.go:22:17", "a call cannot be inside bpf.WithLock's region"},
	{"lock_return", GB026LockTimerShape, Rejected, "main.go:23:4", "return cannot be inside bpf.WithLock's region"},
	{"lock_break", GB000TypeCheck, Rejected, "main.go:22:4", "break not in for, switch, or select statement"},
	{"lock_goto", GB011CapabilityNotProvided, Unknown, "main.go:22:4", "goto is not in the capability table"},
	{"lock_defer", GB011CapabilityNotProvided, Rejected, "main.go:22:4", `needs capability "go.defer"`},
	{"lock_panic", GB011CapabilityNotProvided, Rejected, "main.go:22:4", `needs capability "go.panic"`},
	{"lock_if", GB026LockTimerShape, Rejected, "main.go:22:4", "*ast.IfStmt cannot be inside bpf.WithLock's region"},
	{"lock_outer_assign", GB026LockTimerShape, Rejected, "main.go:23:4", "bpf.WithLock's region cannot assign x, a variable declared outside it"},
	{"lock_field_value", GB001UnsupportedConstruct, Unknown, "main.go:23:3", "variable l has type github.com/yuskesh/go-bpf-mlir/bpf.SpinLock"},
	{"lock_literal", GB016SharedABIShape, Rejected, "main.go:20:18", "record Pair holds a bpf.SpinLock Lock — its value cannot be written as a literal"},
	{"lock_hash", GB026LockTimerShape, Rejected, "main.go:19:5", "a record with a lock or a timer may only be the value of a bpf.Array (not the value of a hash)"},
	{"lock_and_timer", GB016SharedABIShape, Rejected, "main.go:22:2", "record Both has more than one bpf.SpinLock / bpf.Timer field (Lock and T)"},
	{"lock_tc", GB026LockTimerShape, Rejected, "main.go:21:3", "bpf.WithLock may only be used in the body of an xdp program"},
	{"lock_kprobe_map", GB026LockTimerShape, Rejected, "main.go:20:6", "the kprobe program onPoll uses map Pairs, whose value Pair holds a bpf.SpinLock"},
	{"lock_not_literal", GB011CapabilityNotProvided, Unknown, "main.go:21:25", "value of type func()"},
	{"timer_status_discarded", GB017StatusIgnored, Rejected, "main.go:25:3", "the raw status of Timer.Init is discarded"},
	{"timer_unguarded", GB026LockTimerShape, Rejected, "main.go:26:7", "w.T.SetCallback must be inside `if st := w.T.Init(); st == 0 { … }`"},
	{"timer_guard_reassigned", GB026LockTimerShape, Rejected, "main.go:28:8", "w.T.SetCallback must be inside `if st := w.T.Init(); st == 0 { … }`"},
	{"timer_in_loop", GB018LoopShape, Rejected, "main.go:26:8", "the checked pointer w cannot be used inside a loop"},
	{"timer_cb_helper", GB026LockTimerShape, Rejected, "main.go:20:8", "a call cannot be inside the timer callback onFire (only bpf.KtimeNs()"},
	{"timer_cb_wrong_record", GB026LockTimerShape, Rejected, "main.go:26:24", "the callback onFire must be `func onFire(v *Win)`"},
	{"timer_cb_two_maps", GB026LockTimerShape, Rejected, "main.go:33:24", "the callback onFire is bound to map Wins at main.go:28:24 — one callback serves one map"},
	{"timer_user_put", GB026LockTimerShape, Rejected, "main.go:27:11", "Wins.Put would stop a running timer"},
	// tp_btf and local types of kernel structs (& hits the capability check GB011 first, a mismatched ctx type is Go's types)
	{"tp_write", GB027KernelTypeShape, Rejected, "main.go:16:2", "the kernel struct field p.Pid cannot be written"},
	{"tp_addr", GB011CapabilityNotProvided, Rejected, "main.go:16:7", "taking an address"},
	{"tp_deref", GB027KernelTypeShape, Rejected, "main.go:16:8", "the kernel pointer p is dereferenced as a whole"},
	{"tp_alias", GB027KernelTypeShape, Rejected, "main.go:16:7", "the kernel pointer p is assigned"},
	{"tp_nil", GB027KernelTypeShape, Rejected, "main.go:16:5", "the kernel pointer p is compared (a checked kernel pointer is never nil"}, // the message points at the checked shape
	{"tp_loop", GB018LoopShape, Rejected, "main.go:17:24", "the kernel struct field p.Pid cannot be read inside a loop"},
	// tp_gap (missing declarations of earlier unread arguments) became an accepted shape — unread arguments are null in the schema
	{"tp_two_types", GB027KernelTypeShape, Rejected, "main.go:16:6", "argument 0 of the tp_btf program onFork is declared as mm_struct here but as task_struct"},
	{"tp_not_top", GB027KernelTypeShape, Rejected, "main.go:16:3", "bpf.TPArg must be a top-level statement of the tp_btf program body"},
	{"tp_index_var", GB027KernelTypeShape, Rejected, "main.go:16:28", "the argument index of bpf.TPArg must be a constant 0..11"},
	// tp_field_width (an int64 field) became an accepted shape — fields of 8 to 64 bits
	// Local kernel type extensions: unchecked traversal, use in the else arm, unchecked FentryArg, array elements, two readings of one argument, checks in a loop, out-of-range width, out-of-range length, TPArgInt of a struct
	{"kt_ptr_unchecked", GB005NilCheckShape, Rejected, "main.go:28:10", "the kernel pointer field c.MM may be NULL — read it only as `if m := c.MM; m != nil"},
	{"kt_ptr_else_use", GB005NilCheckShape, Rejected, "main.go:31:11", "the kernel pointer is NULL in the else branch"},
	{"kt_fentry_nocheck", GB005NilCheckShape, Rejected, "main.go:26:7", "bpf.FentryArg returns a pointer that may be NULL"},
	{"kt_array_read", GB027KernelTypeShape, Rejected, "main.go:28:17", "the kernel array field c.Comm can only be copied whole into a record field"},
	{"kt_arg_conflict", GB027KernelTypeShape, Rejected, "main.go:27:11", "argument 1 of the tp_btf program onPi is read as nullable task_struct here but as task_struct"},
	{"kt_check_loop", GB018LoopShape, Rejected, "main.go:28:3", "a kernel pointer cannot be checked inside a loop"},
	{"kt_width_bad", GB027KernelTypeShape, Rejected, "main.go:26:2", "field On has type bool — a kernel field is int8 to int64 / uint8 to uint64"},
	{"kt_copy_long", GB027KernelTypeShape, Rejected, "main.go:26:2", "field Name has type [65]byte"},
	{"kt_tpint_struct", GB000TypeCheck, Rejected, "main.go:26:20", "Task does not satisfy bpf.KprobeInt"},
	{"tp_no_mark", GB027KernelTypeShape, Rejected, "main.go:5:6", "Task is not a kernel type"},
	{"tp_no_tag", GB027KernelTypeShape, Rejected, "main.go:7:2", "field Pid needs to be exported and tagged"},
	{"tp_in_fentry", GB000TypeCheck, Rejected, "main.go:14:23", "cannot use ctx (variable of type *bpf.FentryContext) as *bpf.TPBTFContext value"},
	// Hash-family maps and constant Array keys
	{"hash_status_ignored", GB017StatusIgnored, Rejected, "main.go:14:2", "the status of H.Insert is discarded"},
	{"percpu_status_ignored", GB017StatusIgnored, Rejected, "main.go:8:2", "the status of H.Insert is discarded"}, // a negative case of the per-CPU group
	{"hash_atomic_add", GB000TypeCheck, Rejected, "main.go:14:4", "has no field or method AtomicAdd"},             // the hash family has no AtomicAdd (Go's types stop it)
	{"array_delete", GB000TypeCheck, Rejected, "main.go:12:13", "has no field or method Delete"},
	{"hash_key_narrow", GB009MapDeclShape, Rejected, "main.go:11:5", "an integer key must be 32 or 64 bit, got uint16"},
	{"hash_value_bool", GB009MapDeclShape, Rejected, "main.go:11:5", "map H value: bool is neither a fixed-width integer nor a record"},
	{"hash_key_var", GB016SharedABIShape, Rejected, "main.go:14:6", "variable k holds the record Key"},
	{"array_const_key_out", GB009MapDeclShape, Rejected, "main.go:12:19", "the key 2 is outside map Counts (MaxEntries 2)"},
	{"array_const_key_lookup", GB009MapDeclShape, Rejected, "main.go:12:24", "the key 7 is outside map Counts (MaxEntries 2)"},
	// AddOrInit
	{"addinit_record_value", GB016SharedABIShape, Rejected, "main.go:16:6", "H.AddOrInit needs an integer value, but H holds the record Val"},
	{"addinit_ignored", GB017StatusIgnored, Rejected, "main.go:16:2", "the status of H.AddOrInit is discarded"},
	// Bounded loops
	{"loop_n_65", GB018LoopShape, Rejected, "main.go:15:2", "the loop bound 65 is outside [0, 64]"},
	{"loop_var_bound", GB018LoopShape, Rejected, "main.go:16:2", "the loop bound must be a constant"},
	{"loop_depth3", GB018LoopShape, Rejected, "main.go:17:4", "loops nest at most 2 deep"},
	{"loop_product", GB018LoopShape, Rejected, "main.go:16:3", "the nested loop counts multiply to 128"},
	{"loop_forever", GB011CapabilityNotProvided, Rejected, "main.go:15:2", `needs capability "go.unbounded_loop"`},
	{"loop_output_inside", GB018LoopShape, Rejected, "main.go:16:3", "Events.Output cannot be inside a loop"},
	{"loop_check_break_nested", GB018LoopShape, Rejected, "main.go:14:5", "break inside a ctx.Check branch must be the last statement of that branch"},
	{"loop_iv_assign", GB018LoopShape, Rejected, "main.go:17:3", "the loop variable i must not be assigned in the body"},
	{"loop_break_top", GB018LoopShape, Rejected, "main.go:17:3", "an unconditional break at the end of the loop body"},
	{"loop_break_middle", GB018LoopShape, Rejected, "main.go:17:4", "break must be the last statement of its block"},
	{"loop_window_use", GB018LoopShape, Rejected, "main.go:17:16", "the packet window w cannot be used inside a loop"},
	{"loop_bound_mutated", GB018LoopShape, Rejected, "main.go:16:26", "the runtime bound uses n, which the body assigns"},
	{"loop_unroll_big", GB018LoopShape, Rejected, "main.go:15:2", "unrolling a body estimated at 123 op(s) (+4 per copy) 64 times"}, // bpf-mlir's counting (formerly the rough 123 × 64 = 7872)
	// Variable indexes into record arrays
	{"idx_unchecked", GB006NonConstant, Rejected, "main.go:17:20", "the index of p.Arr must be a constant, or a uint32 variable checked by"},
	{"idx_int32", GB014WindowIndex, Rejected, "main.go:17:6", "the index i must be uint32"},
	{"idx_assign_in_guard", GB014WindowIndex, Rejected, "main.go:18:4", "the checked index i must not be assigned inside the range check"},
	{"idx_other_var", GB006NonConstant, Rejected, "main.go:18:21", "the index of p.Arr must be a constant"},
	{"idx_loop_too_long", GB014WindowIndex, Rejected, "main.go:17:22", "the loop counter k runs to 9, beyond len(p.Arr) = 8"},
	{"idx_break_in_guard", GB018LoopShape, Rejected, "main.go:19:6", "break cannot be inside a range check"},
	// sched_cls
	{"tc_xdp_verdict", GB000TypeCheck, Rejected, "main.go:8:9", "cannot use bpf.XDPPass"}, // Go's types keep verdict types from mixing
	{"tc_redirect_stmt", GB008ProgramShape, Rejected, "main.go:8:2", "ctx.Redirect / RedirectIf is a terminator"},
	{"tc_redirect_value", GB008ProgramShape, Rejected, "main.go:8:7", "ctx.Redirect / RedirectIf is a terminator"},
	{"tc_bad_verdict", GB001UnsupportedConstruct, Rejected, "main.go:8:9", "action 3 is not a supported sched_cls verdict (pass / drop)"},
	{"tc_wrong_result", GB008ProgramShape, Rejected, "main.go:7:6", "takes a program context but is not a program"},
	{"tc_redirectif_var", GB006NonConstant, Rejected, "main.go:9:33", "the otherwise action of RedirectIf must be a constant sched_cls verdict"},
	// Exports outside package main
	{"export_nonmain", GB019ExportedBPFFunc, Rejected, "lib.go:7:6", "the eBPF-side function Helper is exported from package lib (not main) — another package could call it and hit the eBPF-only stubs (panic); rename it to helper"},
	{"export_nonmain", GB019ExportedBPFFunc, Rejected, "lib.go:9:6", "rename it to sample (attach from outside the package through a user-side function of this package)"},
	// prog_array slot declarations and tail call shapes (xdp roots of the same package only, double declarations, a constant below MaxEntries)
	{"tail_in_if", GB023TailShape, Rejected, "main.go:15:3", "TailCall must be a top-level statement of the program body"},
	{"tail_in_loop", GB023TailShape, Rejected, "main.go:10:3", "TailCall must be a top-level statement of the program body"},
	{"tail_in_check", GB023TailShape, Rejected, "main.go:10:3", "TailCall must be a top-level statement of the program body"},
	{"tail_twice", GB023TailShape, Rejected, "main.go:11:2", "a program makes at most one tail call"},
	{"tail_else_var", GB006NonConstant, Rejected, "main.go:10:29", "the otherwise action of TailCallIf must be a constant"},
	{"tail_tc", GB000TypeCheck, Rejected, "main.go:9:13", "cannot use ctx (variable of type *bpf.TCIngressContext) as *bpf.XDPContext value"}, // xdp only — Go's types stop it
	{"tail_user", GB003CrossDomainUse, Rejected, "main.go:9:4", "bpf.ProgArray.TailCall is an eBPF-side operation"},
	{"tail_window_outer", GB001UnsupportedConstruct, Unknown, "main.go:9:6", "has type github.com/yuskesh/go-bpf-mlir/bpf.Window, which is not in the supported subset"}, // a window from before the tail call does not reach the fallback
	{"slot_nonconst", GB006NonConstant, Rejected, "main.go:10:26", "the slot of bpf.TailSlot must be a constant"},
	{"slot_range", GB023TailShape, Rejected, "main.go:8:26", "slot 4 of S is outside [0, 4) (MaxEntries)"},
	{"slot_dup", GB023TailShape, Rejected, "main.go:9:26", "slot 1 of S is declared twice (first at main.go:8:9)"},
	{"slot_funcvar", GB023TailShape, Rejected, "main.go:10:29", "must be an xdp program declared in this package, named directly"},
	{"slot_other_pkg", GB023TailShape, Rejected, "main.go:10:29", "must be an xdp program declared in this package, named directly"},
	{"slot_named", GB023TailShape, Rejected, "main.go:8:10", "a tail-call slot is declared alone as `var _ = bpf.TailSlot(&M, slot, Program)`"},
	{"slot_in_func", GB023TailShape, Rejected, "main.go:11:6", "bpf.TailSlot is a declaration, not a runtime call"},
	{"slot_ptr_var", GB023TailShape, Rejected, "main.go:10:22", "the first argument of bpf.TailSlot must be &M"},
	{"slot_ebpf_side", GB003CrossDomainUse, Rejected, "main.go:9:10", "bpf.TailSlot is a user-space operation"},
	// XDP packet rewrites
	{"stale_after_adjust", GB025PacketWrite, Rejected, "main.go:10:22", "window w was checked before ctx.AdjustHead at main.go:9:7"},
	{"stale_after_adjust_merge", GB025PacketWrite, Rejected, "main.go:12:3", "window w was checked before ctx.AdjustHead at main.go:10:8"},
	{"set_tc", GB025PacketWrite, Rejected, "main.go:9:3", "packet writes are xdp-only"},
	{"tail_positive", GB025PacketWrite, Rejected, "main.go:8:21", "the delta of ctx.AdjustTail must be ≤ 0"},
	{"tail_var", GB006NonConstant, Rejected, "main.go:9:21", "the delta of ctx.AdjustTail must be a constant ≤ 0"},
	{"adjust_loop", GB018LoopShape, Rejected, "main.go:9:7", "ctx.AdjustHead cannot be inside a loop"},
	{"adjust_ignored", GB017StatusIgnored, Rejected, "main.go:8:2", "the status of ctx.AdjustHead (0 or a negative errno) is discarded"},
	{"set_out_of_window", GB014WindowIndex, Rejected, "main.go:9:13", "writes bytes [12, 12+4) outside the checked window of 14 bytes"},
	// Two borrows at once — a second borrow that may point at the same value (GB029), and unchanged rules (depth, loop, WithLock, RMW, argument nil checks).
	{"tb_same_var", GB029BorrowAlias, Rejected, "main.go:18:11", "A.Lookup(k) inside the checked branch of p may point to the same value as p (both are values of map A and the keys are not both constants)"},
	{"tb_same_const", GB029BorrowAlias, Rejected, "main.go:15:11", "may point to the same value as p (both are values of map A at the same key 1)"},
	{"tb_param_same", GB029BorrowAlias, Rejected, "main.go:14:10", "p is a pointer parameter of the same value type — it may point into A"},
	{"tb_third", GB001UnsupportedConstruct, Unknown, "main.go:17:4", "at most two borrows at once — this Lookup is inside the checked branches of p and q"},
	{"tb_loop_carry", GB018LoopShape, Rejected, "main.go:17:11", "the checked pointer p cannot be used inside a loop"},
	{"tb_lock_other", GB026LockTimerShape, Rejected, "main.go:23:11", "bpf.WithLock's region can only use the pointer p, not q"},
	{"tb_rmw", GB028NonAtomicRMW, Rejected, "main.go:20:4", "q.S is written from a value read from itself"},
	{"tb_param_nilcheck", GB001UnsupportedConstruct, Unknown, "main.go:20:3", "a nil check of a pointer parameter inside another checked branch is not supported yet"},
	// Helpers with one packet window and one borrow argument — caller conditions (in_range window, checked borrow), unchanged rules (forwarding, writes to the borrow, tc window writes), GB028 origins.
	{"wp_zero_window", GB013SubprogramShape, Rejected, "main.go:22:16", "the packet window argument of classify must be the window w of `if w, ok := ctx.Check(off, n); ok { … }` in the calling program — z is not"},
	{"wp_unchecked_var", GB005NilCheckShape, Rejected, "main.go:20:2", "variable p holds a pointer to a map value"},
	{"wp_forward", GB013SubprogramShape, Rejected, "main.go:17:15", "subprogram classify passes its packet window w on to proto"},
	{"wp_tc_write", GB013SubprogramShape, Rejected, "main.go:18:14", "subprogram stamp writes the packet through its window w (main.go:10:2), but sched_cls program T calls it"},
	{"wp_rmw", GB028NonAtomicRMW, Rejected, "main.go:20:4", "p.Class is written from a value read from itself (through the return value of next)"},
	// Subprograms taking the program context — shape (first argument, static, passable kinds, the caller's ctx) and ops stopped in the callee (attach-dependent reads, invalidation, terminators, locks).
	{"cx_kprobe_arg", GB013SubprogramShape, Rejected, "main.go:9:9", "bpf.KprobeArg reads an attach-specific value, which a subprogram that takes the context cannot do"},
	// UprobeArg in a callee stopped directly, with testdata that satisfies the uprobe path rule (fixture cfix inside the package).
	{"cx_uprobe_arg", GB013SubprogramShape, Rejected, "main.go:10:9", "bpf.UprobeArg reads an attach-specific value, which a subprogram that takes the context cannot do"},
	{"cx_fentry_arg", GB013SubprogramShape, Rejected, "main.go:15:10", "bpf.FentryArg reads an attach-specific value, which a subprogram that takes the context cannot do"},
	{"cx_adjust", GB013SubprogramShape, Rejected, "main.go:9:9", "ctx.AdjustHead changes the packet (it invalidates every window), which a subprogram that takes the context cannot do"},
	{"cx_tail", GB023TailShape, Rejected, "main.go:9:2", "TailCall is only available in the program itself, not in a subprogram"},
	{"cx_lock", GB026LockTimerShape, Rejected, "main.go:16:3", "bpf.WithLock may only be used in the body of an xdp program (bpf-mlir supports spin locks and timers in xdp programs only) — not in a subprogram"},
	{"cx_not_first", GB013SubprogramShape, Rejected, "main.go:8:6", "the program context must be the first parameter"},
	{"cx_global", GB013SubprogramShape, Rejected, "main.go:9:6", "global subprogram etype takes the program context — only a static subprogram can"},
	{"cx_fexit", GB013SubprogramShape, Rejected, "main.go:8:6", "the fexit context cannot be passed to a subprogram"},
	{"cx_nil_ctx", GB013SubprogramShape, Rejected, "main.go:17:29", "the context argument of etype must be the calling program's context parameter"},
	{"cx_redirect", GB005NilCheckShape, Rejected, "main.go:9:7", "Ports's methods are statements"},
	// RingBuf.OutputKernelStr and bpf.KernelStr — OutputStr's rules (tag kernelstr / kernelstr_status) and the direct selector of a kernel string field.
	{"kstr_discarded", GB017StatusIgnored, Rejected, "main.go:21:3", "the status of Events.OutputKernelStr (the raw probe_read_kernel_str status) and whether it was submitted are discarded"},
	{"kstr_no_field", GB016SharedABIShape, Rejected, "main.go:21:10", "Events.OutputKernelStr needs exactly one field tagged `gobpf:\"kernelstr\"` in the event record Ev, found 0"},
	{"kstr_two_fields", GB016SharedABIShape, Rejected, "main.go:22:10", "Events.OutputKernelStr needs exactly one field tagged `gobpf:\"kernelstr\"` in the event record Ev, found 2"},
	{"kstr_not_bytes", GB016SharedABIShape, Rejected, "main.go:21:10", "the `gobpf:\"kernelstr\"` field Name of Ev must be a byte array ([N]uint8 / [N]byte — kernel.read_str writes the string there)"},
	{"kstr_too_long", GB016SharedABIShape, Rejected, "main.go:22:10", "the `gobpf:\"kernelstr\"` field Name of Ev has 65 bytes — kernel.read_str writes into a byte array of 1..64"},
	{"kstr_no_status", GB016SharedABIShape, Rejected, "main.go:20:10", "Events.OutputKernelStr needs exactly one int64 field tagged `gobpf:\"kernelstr_status\"` in the event record Ev, found 0"},
	{"kstr_status_int32", GB016SharedABIShape, Rejected, "main.go:22:10", "the `gobpf:\"kernelstr_status\"` field St of Ev must be int64 (OutputKernelStr writes the raw status of kernel.read_str there)"},
	{"kstr_in_loop", GB018LoopShape, Rejected, "main.go:22:11", "Events.OutputKernelStr cannot be inside a loop"},
	{"kstr_literal", GB027KernelTypeShape, Rejected, "main.go:21:39", "the second argument of Events.OutputKernelStr must be a bpf.KernelStr field of a checked kernel pointer written in place"},
	// GB027 was predicted — in fact the local variable type check (GB001 Unknown — like UprobeStr's uprobe_str_elsewhere) and Go's type check (GB000 — KernelStr is not comparable) stop first.
	{"kstr_var", GB001UnsupportedConstruct, Unknown, "main.go:20:6", "variable s has type github.com/yuskesh/go-bpf-mlir/bpf.KernelStr, which is not in the supported subset"},
	{"kstr_read", GB001UnsupportedConstruct, Unknown, "main.go:21:3", "variable s has type github.com/yuskesh/go-bpf-mlir/bpf.KernelStr, which is not in the supported subset"},
	{"kstr_compare", GB000TypeCheck, Rejected, "main.go:23:6", "invalid operation: p.Filename == p.Filename (struct containing [0]func() cannot be compared)"},
	// sk_lookup's SockMap.Assign / SockHash.Assign.
	{"skas_discard", GB017StatusIgnored, Rejected, "main.go:9:2", "the raw status of Socks.Assign (sk_assign) and whether the slot held a socket are discarded"},
	{"skas_flags_var", GB006NonConstant, Rejected, "main.go:10:30", "the flags of Socks.Assign must be a constant: 0, bpf.SkAssignReplace, bpf.SkAssignNoReuseport or both joined with |"},
	{"skas_loop", GB018LoopShape, Rejected, "main.go:10:10", "Socks.Assign cannot be called inside a loop"},
	{"skas_xdp", GB000TypeCheck, Rejected, "main.go:9:22", "cannot use ctx (variable of type *bpf.XDPContext) as *bpf.SkLookupContext value in argument to Socks.Assign"},
	{"skas_sub", GB013SubprogramShape, Rejected, "main.go:8:6", "the sk_lookup context cannot be passed to a subprogram"},
	{"skas_user", GB003CrossDomainUse, Rejected, "main.go:14:15", "bpf.SockMap.Assign is an eBPF-side operation"},
	// bpf.SysBpf / bpf.SysClose in syscall programs.
	{"sysb_discard", GB017StatusIgnored, Rejected, "main.go:11:2", "the raw status of bpf.SysBpf is discarded"},
	{"sysb_close_discard", GB017StatusIgnored, Rejected, "main.go:7:2", "the raw status of bpf.SysClose is discarded"},
	{"sysb_cmd_var", GB006NonConstant, Rejected, "main.go:12:22", "the cmd of bpf.SysBpf must be the constant bpf.SysBpfMapCreate, bpf.SysBpfMapGetFdByID or bpf.SysBpfMapFreeze"},
	{"sysb_loop", GB018LoopShape, Rejected, "main.go:8:7", "bpf.SysClose cannot be called inside a loop"},
	{"sysb_xdp", GB000TypeCheck, Rejected, "main.go:11:17", "cannot use ctx (variable of type *bpf.XDPContext) as *bpf.SyscallContext value in argument to bpf.SysBpf"},
	{"sysb_notrec", GB008ProgramShape, Rejected, "main.go:7:43", "bpf.SysBpf takes a record value as attr"},
	{"sysb_sub", GB013SubprogramShape, Rejected, "main.go:6:6", "the syscall context cannot be passed to a subprogram"},
	{"sysb_user", GB003CrossDomainUse, Rejected, "main.go:12:10", "bpf.SysClose is an eBPF-side operation"},
	{"sysb_in_if", GB008ProgramShape, Rejected, "main.go:8:7", "bpf.SysClose must be a top-level statement of the syscall program body"},
	// Periodic timers — inside the callback, only an if and a Start of its own timer are added.
	{"tmrp_init", GB026LockTimerShape, Rejected, "main.go:15:6", "Timer.Init cannot be inside the timer callback tick — a callback may only restart its own timer"},
	{"tmrp_setcb", GB026LockTimerShape, Rejected, "main.go:16:7", "Timer.SetCallback cannot be inside the timer callback tick"},
	{"tmrp_discard", GB017StatusIgnored, Rejected, "main.go:16:3", "the raw status of Timer.Start in the timer callback tick is discarded"},
	{"tmrp_if_map", GB026LockTimerShape, Rejected, "main.go:18:3", "a call statement cannot be inside the timer callback tick"},
	{"tmrp_other", GB026LockTimerShape, Rejected, "main.go:16:6", "the timer callback tick can only use the pointer v, not w"},
}

// Negative tests — pin the reason code, verdict, position and wording.
func TestNegative(t *testing.T) {
	for _, c := range negativeCases {
		t.Run(c.dir, func(t *testing.T) {
			res, err := analyzeCached(caseDir(c.dir))
			if err != nil {
				t.Fatal(err)
			}
			if res.OK() || res.MLIR != nil || res.Schema != nil {
				t.Fatal("expected a blocking diagnostic and no output")
			}
			found := false
			for _, d := range res.Diagnostics {
				if d.Code == c.code && d.Verdict == c.verdict && posString(d.Pos) == c.pos && strings.Contains(d.Msg, c.msg) {
					found = true
				}
			}
			if !found {
				for _, d := range res.Diagnostics {
					t.Log(d.String())
				}
				t.Fatalf("missing %s %s at %s containing %q", c.code, c.verdict, c.pos, c.msg)
			}
		})
	}
}

// Fail closed — removing a bpf identifier from the table makes its use stop as Unknown (GB002).
func TestFailClosed(t *testing.T) {
	key := bpfPkg + ".Array.Update"
	saved := apiTable[key]
	delete(apiTable, key)
	defer func() { apiTable[key] = saved }()
	res, err := Analyze(exampleDir(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Diagnostics {
		if d.Code == GB002UnsupportedCall && d.Verdict == Unknown && strings.Contains(d.Msg, "bpf.Array.Update is not in gobpf's API table") {
			if res.OK() {
				t.Fatal("an Unknown diagnostic must block generation")
			}
			return
		}
	}
	t.Fatalf("no GB002 Unknown for a removed table entry: %v", res.Diagnostics)
}

// Golden JSON of the domain verdicts (roots + reachability, funcvalue edges).
func TestDomainGraphGolden(t *testing.T) {
	res := analyzeOK(t, exampleDir(t))
	got, err := res.GraphJSON()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden", "xdpcount.domain-graph.json")
	if os.Getenv("GOBPF_UPDATE_GOLDEN") == "1" {
		os.MkdirAll(filepath.Dir(golden), 0o755)
		os.WriteFile(golden, got, 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("domain graph differs from %s:\n%s", golden, got)
	}
	// Subprogram reachability is computed the same way (lowering rejects it, but the domain is ebpf).
	sub, err := Analyze(filepath.Join("testdata", "subprogram_call"))
	if err != nil {
		t.Fatal(err)
	}
	var helperDomain string
	for _, n := range sub.Graph.Nodes {
		if n.Func == "helper" {
			helperDomain = n.Domain
		}
	}
	if helperDomain != "ebpf" {
		t.Fatalf("helper reached from a program should be in the ebpf domain, got %q", helperDomain)
	}
}

// A GB011 with a path is reported once (not again in intermediate functions), and the path runs from the root to the forbidden construct.
func TestCapabilityPathReportedOnce(t *testing.T) {
	for dir, want := range map[string][]string{
		"chain3_fmt":    {"P", "A", "B", "C", "call to fmt.Println"},
		"chain_unknown": {"P", "A", "B", "SwitchStmt is not in the capability table"},
	} {
		res, err := Analyze(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Diagnostics) != 1 {
			t.Fatalf("%s: want exactly one diagnostic, got %v", dir, res.Diagnostics)
		}
		if got := strings.Join(res.Diagnostics[0].Path, " → "); got != strings.Join(want, " → ") {
			t.Fatalf("%s: path %q, want %q", dir, got, strings.Join(want, " → "))
		}
	}
}

// FuncKey is an instance key — instances of the same Origin with different type arguments get different keys, non-generic functions have empty TypeArgs.
func TestFuncKeyDistinguishesInstances(t *testing.T) {
	const src = `package p
func Id[T any](x T) T { return x }
func Plain(x int) int { return x }
var a = Id[int]
var b = Id[string]
var c = Id[int]
var d = Plain
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
	if _, err := (&types.Config{}).Check("p", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	keys := map[string]FuncKey{}
	for id := range info.Uses {
		if k, ok := instanceKey(info, id); ok {
			keys[fset.Position(id.Pos()).String()] = k
		}
	}
	var ka, kb, kc, kd FuncKey
	for pos, k := range keys {
		switch {
		case strings.HasPrefix(pos, "p.go:4:"):
			ka = k
		case strings.HasPrefix(pos, "p.go:5:"):
			kb = k
		case strings.HasPrefix(pos, "p.go:6:"):
			kc = k
		case strings.HasPrefix(pos, "p.go:7:"):
			kd = k
		}
	}
	if ka.Fn == nil || ka.Fn != kb.Fn {
		t.Fatalf("Id[int] and Id[string] must share the Origin: %+v %+v", ka, kb)
	}
	if ka == kb {
		t.Fatalf("Id[int] and Id[string] must be different keys: %+v", ka)
	}
	if ka != kc {
		t.Fatalf("two uses of Id[int] must be the same key: %+v %+v", ka, kc)
	}
	if kd.TypeArgs != "" {
		t.Fatalf("a non-generic function has no type arguments in its key: %+v", kd)
	}
}

// A unit control that reaches it — passing a constant that does not fit straight to constant() gives GB015 (not a silent 0).
func TestConstantOutOfRangeIsInternalError(t *testing.T) {
	a := &analyzer{fset: token.NewFileSet(), dir: "."}
	l := &lowerer{a: a, name: "F", b: &strings.Builder{}}
	l.constant(constant.MakeInt64(300), vtype{bits: 8})
	if !l.failed || len(a.diags) != 1 || a.diags[0].Code != GB015InternalEmitter || !strings.Contains(a.diags[0].Msg, "constant 300 does not fit i8") {
		t.Fatalf("want one GB015 for 300 in i8, got failed=%v %v", l.failed, a.diags)
	}
}

// Capability errors and shape errors in one run — a golden of report count and order (functions with capability errors are not lowered, callers report no false errors).
func TestCapabilityAndShapeErrorsTogether(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "cap_and_shape"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range res.Diagnostics {
		got = append(got, fmt.Sprintf("%s %s %s", posString(d.Pos), d.Code, strings.Join(d.Path, " → ")))
	}
	want := []string{
		"main.go:13:2 GB011 P → Bad → call to fmt.Println",
		"main.go:18:43 GB012 Shape",
		"main.go:24:29 GB012 P",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// SharedABI is split by a kind tag — a record's SharedABI cannot be read as an integer (intType is false), its mlir is the record type.
func TestSharedABIKinds(t *testing.T) {
	i := sharedABIOfInt(types.Typ[types.Uint32], IntType{Bits: 32})
	if it, ok := i.intType(); !ok || it.Bits != 32 || i.mlir() != "i32" || i.Kind != ABIInt {
		t.Fatalf("int ABI: %+v", i)
	}
	r := SharedABI{Kind: ABIRecord, Size: 24, Align: 8, Record: &RecordABI{Symbol: "Stats"}}
	if _, ok := r.intType(); ok {
		t.Fatal("a record ABI must not read as an integer")
	}
	if r.mlir() != `!ebpf.record<"Stats", 24>` {
		t.Fatalf("record mlir: %s", r.mlir())
	}
	if r.Int != nil {
		t.Fatal("a record ABI has no integer field")
	}
}

// Records outside the rules stop with GB016 (map value shapes outside with GB009), with position and reason. Implicit padding names the needed `_ [N]byte`.
// testdata's Nested (field G is the named record Gap2) became an accepted nested record — that error was removed (nested negative cases are in TestNestedRecordRules).
func TestRecordRules(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "rec_rules"))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.MLIR != nil || res.Schema != nil {
		t.Fatal("expected blocking diagnostics and no output")
	}
	want := []struct {
		code Code
		pos  string
		msg  string
	}{
		{GB016SharedABIShape, "main.go:7:2", "3 bytes of implicit padding before field B (offset 4) — declare it explicitly as `_ [3]byte`"},
		{GB016SharedABIShape, "main.go:10:6", "record Tail has 7 bytes of implicit trailing padding — declare it explicitly as `_ [7]byte` at the end"},
		{GB016SharedABIShape, "main.go:16:2", "field A needs a `schema:\"…\"` tag"},
		{GB016SharedABIShape, "main.go:20:2", "field a must be exported"},
		{GB016SharedABIShape, "main.go:24:2", "field On has type bool"},
		{GB016SharedABIShape, "main.go:29:2", "field P has type *uint64"},
		{GB016SharedABIShape, "main.go:33:2", "field S has type []uint8"},
		{GB016SharedABIShape, "main.go:37:2", "field S has type string"},
		{GB016SharedABIShape, "main.go:41:2", "field F has type float64"},
		{GB016SharedABIShape, "main.go:45:2", "field N has type uint"},
		{GB016SharedABIShape, "main.go:58:2", `schema name "x" is used twice`},
		{GB016SharedABIShape, "main.go:63:2", "a blank field must be explicit padding of type [N]byte, got [1]uint16"},
		{GB009MapDeclShape, "main.go:82:2", "map M14 value: [4]uint32 is neither a fixed-width integer nor a record"},
		{GB009MapDeclShape, "main.go:83:2", "an integer value must be 32 or 64 bit, got uint16"},
		{GB009MapDeclShape, "main.go:84:2", "is neither a fixed-width integer nor a record"},
	}
	if len(res.Diagnostics) != len(want) {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatalf("%d diagnostics, want %d (each rule once — Named uint64 is accepted)", len(res.Diagnostics), len(want))
	}
	for i, w := range want {
		d := res.Diagnostics[i]
		if d.Code != w.code || d.Verdict != Rejected || posString(d.Pos) != w.pos || !strings.Contains(d.Msg, w.msg) {
			t.Errorf("diagnostic %d: got %s, want %s at %s containing %q", i, d.String(), w.code, w.pos, w.msg)
		}
	}
}

// Discarding the status with an explicit `_ =` and using the status as a condition are accepted (GB017 is for expression statements only).
func TestHashStatusExplicitDiscardAccepted(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "hash_blank_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("`_ = H.Insert(…)` and `if st := H.Delete(…); st == -bpf.ENOENT` must be accepted")
	}
	for _, want := range []string{`flags "noexist"`, "ebpf.map.try_delete", "arith.cmpi eq"} {
		if !strings.Contains(string(res.MLIR), want) {
			t.Errorf("the .mlir lacks %q", want)
		}
	}
}

// The errno in AddOrInit's lowering is Linux's value (checked against unix — no hand-written numbers pinned).
func TestAddOrInitErrno(t *testing.T) {
	if errEEXIST != int(unix.EEXIST) || errENOENT != int(unix.ENOENT) {
		t.Fatalf("errEEXIST %d / errENOENT %d, unix %d / %d", errEEXIST, errENOENT, int(unix.EEXIST), int(unix.ENOENT))
	}
}

// Outside package main, the shape where eBPF-side functions are unexported and outside attaches go through exported user-side functions is accepted.
func TestExportNonMainLowercaseAccepted(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "export_nonmain_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("lowercase eBPF-side functions in a non-main package must be accepted")
	}
}

// Proving the bound of a variable Array key — provable shapes get a proof comment in the .mlir with no diagnostic, others are Conditional (GB020) without stopping generation.
func TestArrayKeyProof(t *testing.T) {
	ok, err := Analyze(filepath.Join("testdata", "keyproof_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok.OK() || len(ok.Diagnostics) != 0 {
		for _, d := range ok.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("mask / % / clamp / loop counter / constant / shift keys must be proven without a diagnostic")
	}
	if n := strings.Count(string(ok.MLIR), "// key proven < MaxEntries 8 of Counts"); n != 7 {
		t.Fatalf("want 7 proof comments, got %d", n)
	}
	cond, err := Analyze(filepath.Join("testdata", "keyproof_cond"))
	if err != nil {
		t.Fatal(err)
	}
	if !cond.OK() || cond.MLIR == nil {
		t.Fatal("unproven keys are Conditional — generation must not stop")
	}
	want := []string{"main.go:14:19", "main.go:20:19", "main.go:25:19", "main.go:32:19"}
	var got []string
	for _, d := range cond.Diagnostics {
		if d.Code != GB020ArrayKeyUnproven || d.Verdict != Conditional || !strings.Contains(d.Msg, "not proven < MaxEntries (8)") {
			t.Errorf("unexpected diagnostic %s", d.String())
		}
		got = append(got, posString(d.Pos))
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Conditional positions %v, want %v (subprogram result / assigned after the clamp / clamp beyond MaxEntries / one arm only)", got, want)
	}
}

// A sum whose bound exceeds the type's maximum (it may wrap) and a conversion after a signed % are not proofs.
func TestArrayKeyProofWrapAndSigned(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "keyproof_wrap"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range res.Diagnostics {
		if d.Code != GB020ArrayKeyUnproven || d.Verdict != Conditional {
			t.Errorf("unexpected diagnostic %s", d.String())
		}
		got = append(got, posString(d.Pos))
	}
	want := []string{"main.go:16:19", "main.go:17:19", "main.go:18:19"} // a sum that may reach 8, overflow of a 3-term sum, a signed %
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Conditional at %v, want %v", got, want)
	}
	if n := strings.Count(string(res.MLIR), "// key proven"); n != 1 {
		t.Fatalf("only uint32(s)%%8 is proven, got %d proof comments", n)
	}
}

// gobpf.AttachTCX(objs, fn, …) on the user side of package main is an API that may take a program function value (once missing from the table —
// _test.go files are outside the frontend's analysis, so GB004 first appeared with an example calling AttachTCX from package main).
func TestAttachTCXTakesProgramValue(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "attach_tcx_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("gobpf.AttachTCX(objs, in, …) in package main must be accepted")
	}
	n := 0
	for _, e := range res.Graph.Edges {
		if e.Kind == "funcvalue" && strings.HasSuffix(e.Via, ".AttachTCX") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d funcvalue edges via AttachTCX, want 2", n)
	}
}
