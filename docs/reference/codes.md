<!-- Generated — do not edit by hand. -->

# Reason codes (GB000 onward)

Target: bpf-mlir `v1.20.0` (commit d3e13842). The tables follow what the ebpf-compile of this version accepts and rejects.

The codes of the frontend's diagnostics (`internal/frontend/result.go`). **Verdict**: Rejected (refused by a known rule) and Unknown (not in the table — fail closed) stop generation. Conditional (GB020, GB024) does not stop generation; it stays in the go generate output and in the conditional section of the generated file. "Examples that stop" are the location and message in the negative-test testdata (`internal/frontend/testdata/<dir>`) — `TestNegative` checks that each stops as this table says.

| Code | Name | Meaning |
|---|---|---|
| [GB000](#gb000-typecheck) | TypeCheck | a Go type error (including references to generated identifiers) |
| [GB001](#gb001-unsupportedconstruct) | UnsupportedConstruct | a construct not in the table |
| [GB002](#gb002-unsupportedcall) | UnsupportedCall | a call or identifier not in the table |
| [GB003](#gb003-crossdomainuse) | CrossDomainUse | use of the other side's API |
| [GB004](#gb004-unknownedge) | UnknownEdge | an edge that cannot be followed statically (function values, method values, interfaces) |
| [GB005](#gb005-nilcheckshape) | NilCheckShape | outside the nil check shape |
| [GB006](#gb006-nonconstant) | NonConstant | a non-constant where a constant is required |
| [GB007](#gb007-reservedname) | ReservedName | the reserved prefix gobpf_ |
| [GB008](#gb008-programshape) | ProgramShape | has a context parameter but is not a program shape |
| [GB009](#gb009-mapdeclshape) | MapDeclShape | outside the map declaration shape |
| [GB010](#gb010-recursion) | Recursion | recursion in eBPF side functions (with the cycle path) |
| [GB011](#gb011-capabilitynotprovided) | CapabilityNotProvided | a capability the root's kind does not provide (with the path) |
| [GB012](#gb012-integerrule) | IntegerRule | an integer rule (shift count, divisor) |
| [GB013](#gb013-subprogramshape) | SubprogramShape | outside the subprogram shape (arguments, results, values that cannot be passed) |
| [GB014](#gb014-windowindex) | WindowIndex | a packet window index out of range |
| [GB015](#gb015-internalemitter) | InternalEmitter | an internal frontend error (the emitter fails closed) |
| [GB016](#gb016-sharedabishape) | SharedABIShape | outside the shared type shape (SharedABI — record / array) |
| [GB017](#gb017-statusignored) | StatusIgnored | an expression statement discarding a map operation's status (int64) (make it explicit with `_ =`) |
| [GB018](#gb018-loopshape) | LoopShape | outside the bounded loop shape (constant count ≤ 64, nesting 2, things not allowed in the body) |
| [GB019](#gb019-exportedbpffunc) | ExportedBPFFunc | an exported eBPF side function outside package main (a path to a stub panic when called from another package) |
| [GB020](#gb020-arraykeyunproven) | ArrayKeyUnproven | an Array variable key that cannot be proven below MaxEntries (Conditional — out of range silently does nothing) |
| [GB021](#gb021-atomicshape) | AtomicShape | outside the bpf.AtomicAdd use shape (other than &p.F, an array element, an offset not a multiple of the width) |
| [GB022](#gb022-locrange) | LocRange | an op loc outside the range of BTF line_info (column > 1023, line > 2^20 — bpf-mlir refuses it) |
| [GB023](#gb023-tailshape) | TailShape | outside the shape of prog_array slot declarations (bpf.TailSlot) and tail calls (TailCall / TailCallIf) |
| [GB024](#gb024-compilewarning) | CompileWarning | an ebpf-compile warning (rc 0 — a ref.index index reached by a constant and an unknown value on different paths); Conditional |
| [GB025](#gb025-packetwrite) | PacketWrite | outside the XDP packet rewrite shape (writes to a sched_cls window, an old window after a helper, a positive AdjustTail delta) |
| [GB026](#gb026-locktimershape) | LockTimerShape | outside the spin lock / timer shape (calls, escapes and outer assignments in a WithLock region, starting outside Init == 0, the callback shape, other than xdp) |
| [GB027](#gb027-kerneltypeshape) | KernelTypeShape | outside the shape of tp_btf and kernel struct local types (the TPArg shape, kernel type declarations, uses of a kernel pointer other than reads) |
| [GB028](#gb028-nonatomicrmw) | NonAtomicRMW | a non-atomic read-modify-write of a shared (not per-CPU) map value (op=, ++, = reading the same path back, Update with a value of the same map) |
| [GB029](#gb029-borrowalias) | BorrowAlias | two borrows may point at the same value (same map with keys not shown to be different constants, a Lookup inside a borrow argument of the same type) |

## GB000 TypeCheck

- **Meaning**: a Go type error (including references to generated identifiers)
- **Verdict**: rejected
- **Fix**: fix the Go type error (the same message as go build). Do not refer to identifiers of the generated file (`gobpf_…`) from the source
- **Examples that stop**:
  - `testdata/act_mark_read` `main.go:9:27` — ctx.Mark undefined (type *bpf.TCActContext has no field or method Mark)
  - `testdata/array_delete` `main.go:12:13` — has no field or method Delete
  - `testdata/atomic_16bit` `main.go:18:3` — uint16 does not satisfy ~uint32 | ~uint64 | ~int32 | ~int64
  - `testdata/cga_notcg` `main.go:11:8` — A.TaskUnder undefined (type bpf.Array[uint32, uint64] has no field or method TaskUnder)
  - `testdata/cgdev_lsmret` `main.go:7:9` — cannot use bpf.LSMAllow (constant 0 of int32 type bpf.LSMRet) as bpf.CgroupAction value
  - `testdata/cgdev_write` `main.go:7:6` — ctx.SetMajor undefined (type *bpf.CgroupDeviceContext has no field or method SetMajor)
  - … and 59 more (`negativeCases`)

## GB001 UnsupportedConstruct

- **Meaning**: a construct not in the table
- **Verdict**: rejected / unknown
- **Fix**: rewrite it in a form the table has — for example: return only as the last statement of a program, a side-effect-free expression on the right of && / ||, a chain of if statements instead of switch
- **Examples that stop**:
  - `testdata/act_bad_verdict` `main.go:7:9` — action 7 is not a supported sched_act verdict (ok / shot / pipe)
  - `testdata/act_two_ifs` `main.go:7:3` — return is only supported as the last statement
  - `testdata/cw_int_star` `main.go:9:2` — assignment target must be a local variable
  - `testdata/fentry_comm_outside` `main.go:9:6` — bpf.CurrentComm() may only be the value of a [16]uint8 field in a ring buffer event literal
  - `testdata/fmodret_select` `main.go:13:22` — are both evaluated before the choice
  - `testdata/ksess_range` `main.go:9:9` — the kprobe_session program returns 2, outside 0..1
  - … and 30 more (`negativeCases`)

## GB002 UnsupportedCall

- **Meaning**: a call or identifier not in the table
- **Fix**: use only the bpf / gobpf identifiers listed in docs/reference/api.md (an identifier not in the table stops, fail closed)
- **Example**: `TestFailClosed` (removing bpf.Array.Update from the table turns its use in examples/xdpcount into an Unknown GB002 — "bpf.Array.Update is not in gobpf's API table". Every exported bpf identifier is in the table, so no testdata negative case can be written)

## GB003 CrossDomainUse

- **Meaning**: use of the other side's API
- **Verdict**: rejected
- **Fix**: use eBPF-side operations in functions reachable from a program, and user-space operations (Get / Put / Load …) in functions not reachable from a program. Split a function called from both
- **Examples that stop**:
  - `testdata/atomic_user` `main.go:22:6` — bpf.AtomicAdd is an eBPF-side operation
  - `testdata/ebpf_calls_user_method` `main.go:8:9` — bpf.Array.Get is a user-space operation
  - `testdata/global_ebpf_set` `main.go:8:8` — bpf.Config.Set is a user-space operation
  - `testdata/global_user_add` `main.go:13:4` — bpf.Global.Add is an eBPF-side operation
  - `testdata/kl_user_take` `main.go:11:12` — bpf.Queue.Take is a user-space operation
  - `testdata/kprobe_arg_user` `main.go:13:13` — bpf.KprobeArg is an eBPF-side operation
  - … and 18 more (`negativeCases`)

## GB004 UnknownEdge

- **Meaning**: an edge that cannot be followed statically (function values, method values, interfaces)
- **Verdict**: unknown
- **Fix**: use a program function value only as an argument of gobpf.AttachXDP / AttachTCX / AttachFentry / AttachFexit, Objects.Program and bpf.TailSlot. Call a method value directly
- **Examples that stop**:
  - `testdata/pkgvar_bpf` `main.go:14:12` — the eBPF-side function G is used as a value
  - `testdata/program_as_value` `main.go:12:7` — is used as a value
  - `testdata/user_callback_bpf` `main.go:17:11` — the eBPF-side function G is used as a value
  - `testdata/user_var_bpf` `main.go:15:7` — the eBPF-side function G is used as a value

## GB005 NilCheckShape

- **Meaning**: outside the nil check shape
- **Verdict**: rejected
- **Fix**: use the form `if p := M.Lookup(k); p != nil { … }` / `if w, ok := ctx.Check(off, n); ok { … }`, and use the checked value only inside the checked branch
- **Examples that stop**:
  - `testdata/cx_redirect` `main.go:9:7` — Ports's methods are statements
  - `testdata/deref_in_else` `main.go:10:21` — use of p outside the checked branch
  - `testdata/iter_seq_bare` `main.go:15:6` — SeqFile.Write needs the checked pointer of `if s := ctx.Seq(); s != nil { … }`
  - `testdata/kt_fentry_nocheck` `main.go:26:7` — bpf.FentryArg returns a pointer that may be NULL
  - `testdata/kt_ptr_else_use` `main.go:31:11` — the kernel pointer is NULL in the else branch
  - `testdata/kt_ptr_unchecked` `main.go:28:10` — the kernel pointer field c.MM may be NULL — read it only as `if m := c.MM; m != nil
  - … and 24 more (`negativeCases`)

## GB006 NonConstant

- **Meaning**: a non-constant where a constant is required
- **Verdict**: rejected
- **Fix**: write a constant (MaxEntries, the verdict, the Check length, the window index, the AdjustTail delta, the TailSlot slot, the else verdict)
- **Examples that stop**:
  - `testdata/global_optional_var` `main.go:7:38` — global A: Optional must be a constant
  - `testdata/idx_other_var` `main.go:18:21` — the index of p.Arr must be a constant
  - `testdata/idx_unchecked` `main.go:17:20` — the index of p.Arr must be a constant, or a uint32 variable checked by
  - `testdata/kl_flag_var` `main.go:15:18` — the flag of Q.Push must be the constant bpf.PushAny or bpf.PushExist
  - `testdata/ksess_computed` `main.go:15:9` — the returned value of the kprobe_session program must be a constant
  - `testdata/lsm_deny_var` `main.go:10:21` — the errno of bpf.LSMDeny must be a constant 1..4095
  - … and 25 more (`negativeCases`)

## GB007 ReservedName

- **Meaning**: the reserved prefix gobpf_
- **Verdict**: rejected
- **Fix**: do not use names starting with `gobpf_` (the generated file uses them)
- **Examples that stop**:
  - `testdata/lpm_record_prefix` `main.go:5:6` — uses the prefix "gobpf_" reserved
  - `testdata/reserved_name` `main.go:7:5` — "gobpf_mine" uses the prefix "gobpf_"

## GB008 ProgramShape

- **Meaning**: has a context parameter but is not a program shape
- **Verdict**: rejected
- **Fix**: a program is a top-level `func(ctx *bpf.<Context>) <verdict type>` (fentry / fexit have no result and take a directive) — docs/reference/kinds.md
- **Examples that stop**:
  - `testdata/cga_skbctx` `main.go:11:17` — the first argument of CG.SkbUnder must be the program's context parameter
  - `testdata/cga_skbxdp` `main.go:13:5` — CG.SkbUnder asks about the skb's socket — it may only be called in the body of a tc program
  - `testdata/cgdev_directive` `main.go:7:1` — //gobpf:cgroup_device is only allowed right above
  - `testdata/ext_argtype` `main.go:19:16` — bpf.ExtArg[int32](ctx, 0): argument 0 of g is uint32 — the type argument must be identical
  - `testdata/ext_noprog` `main.go:17:1` — someone_elses_prog is not a program of this package
  - `testdata/ext_notcalled` `main.go:21:1` — program tgt does not call g
  - … and 134 more (`negativeCases`)

## GB009 MapDeclShape

- **Meaning**: outside the map declaration shape
- **Verdict**: rejected
- **Fix**: declare a map at package level as `var M = bpf.<Map>[K, V]{MaxEntries: N}` and use it only as a method receiver (no assignment, address or copy)
- **Examples that stop**:
  - `testdata/array_const_key_lookup` `main.go:12:24` — the key 7 is outside map Counts (MaxEntries 2)
  - `testdata/array_const_key_out` `main.go:12:19` — the key 2 is outside map Counts (MaxEntries 2)
  - `testdata/global_copy` `main.go:14:8` — global variable A may only be used as the receiver of its methods
  - `testdata/hash_key_narrow` `main.go:11:5` — an integer key must be 32 or 64 bit, got uint16
  - `testdata/hash_value_bool` `main.go:11:5` — map H value: bool is neither a fixed-width integer nor a record
  - `testdata/lpm_no_max` `main.go:5:9` — map T: MaxEntries is required
  - … and 19 more (`negativeCases`)

## GB010 Recursion

- **Meaning**: recursion in eBPF side functions (with the cycle path)
- **Verdict**: rejected
- **Fix**: remove the cycle of eBPF-side function calls (BPF-to-BPF calls cannot recurse)
- **Examples that stop**:
  - `testdata/recursion_direct` `main.go:7:34` — recursion among eBPF-side functions
  - `testdata/recursion_mutual` `main.go:9:34` — recursion among eBPF-side functions

## GB011 CapabilityNotProvided

- **Meaning**: a capability the root's kind does not provide (with the path)
- **Verdict**: rejected / unknown
- **Fix**: remove from the functions on the path the constructs whose capability the kind does not provide (heap, string, float, goroutine, unbounded loop …) — the capabilities in docs/reference/kinds.md
- **Examples that stop**:
  - `testdata/atomic_addr_outside` `main.go:18:8` — taking an address (&)
  - `testdata/chain3_fmt` `main.go:12:2` — C needs capability "go.runtime" (call to fmt.Println)
  - `testdata/chain_unknown` `main.go:9:2` — B needs capability "unknown"
  - `testdata/float_type` `main.go:8:7` — needs capability "go.float"
  - `testdata/lock_defer` `main.go:22:4` — needs capability "go.defer"
  - `testdata/lock_goto` `main.go:22:4` — goto is not in the capability table
  - … and 11 more (`negativeCases`)

## GB012 IntegerRule

- **Meaning**: an integer rule (shift count, divisor)
- **Verdict**: rejected
- **Fix**: make the shift count a constant within the width and the divisor a non-zero constant (a signed −1 is not allowed — MinInt / −1)
- **Examples that stop**:
  - `testdata/div_minus_one` `main.go:7:36` — a signed division by the constant -1 is rejected
  - `testdata/div_variable` `main.go:7:41` — the divisor must be a non-zero constant
  - `testdata/shift_variable` `main.go:7:42` — shift count must be a constant
  - `testdata/shift_width` `main.go:7:39` — shift count 32 is outside [0, 32) for i32

## GB013 SubprogramShape

- **Meaning**: outside the subprogram shape (arguments, results, values that cannot be passed)
- **Verdict**: rejected
- **Fix**: a subprogram takes up to five arguments (integers and bool, the program context as the first argument, one packet window, one borrowed map value) and one result, ending in `return <value>` — move the form the message names (forwarding, a global's context, an attach-specific read, …) to the caller
- **Examples that stop**:
  - `testdata/act_callee` `main.go:7:6` — the sched_act context cannot be passed to a subprogram
  - `testdata/cw_lock_rec` `main.go:14:6` — subprogram setN parameter p: a pointer to something other than a map value
  - `testdata/cx_adjust` `main.go:9:9` — ctx.AdjustHead changes the packet (it invalidates every window), which a subprogram that takes the context cannot do
  - `testdata/cx_fentry_arg` `main.go:15:10` — bpf.FentryArg reads an attach-specific value, which a subprogram that takes the context cannot do
  - `testdata/cx_fexit` `main.go:8:6` — the fexit context cannot be passed to a subprogram
  - `testdata/cx_global` `main.go:9:6` — global subprogram etype takes the program context — only a static subprogram can
  - … and 40 more (`negativeCases`)

## GB014 WindowIndex

- **Meaning**: a packet window index out of range
- **Verdict**: rejected
- **Fix**: make the window read / write index a constant within the Check length (i + width ≤ n). Lengthen the Check if it is too short
- **Examples that stop**:
  - `testdata/idx_assign_in_guard` `main.go:18:4` — the checked index i must not be assigned inside the range check
  - `testdata/idx_int32` `main.go:17:6` — the index i must be uint32
  - `testdata/idx_loop_too_long` `main.go:17:22` — the loop counter k runs to 9, beyond len(p.Arr) = 8
  - `testdata/nest_guard_assign` `main.go:21:4` — the checked index i must not be assigned inside the range check
  - `testdata/set_out_of_window` `main.go:9:13` — writes bytes [12, 12+4) outside the checked window of 14 bytes
  - `testdata/sockopt_index` `main.go:8:13` — outside the checked window of 4 bytes
  - … and 2 more (`negativeCases`)

## GB015 InternalEmitter

- **Meaning**: an internal frontend error (the emitter fails closed)
- **Fix**: nothing for the user to fix — a frontend bug. Report it with the input Go source
- **Example**: assumed unreachable — `TestInternalEmitterUnreachable` checks that no input in the repository produces it

## GB016 SharedABIShape

- **Meaning**: outside the shared type shape (SharedABI — record / array)
- **Verdict**: rejected
- **Fix**: a record is a named struct of the same package whose fields are fixed-width integers or arrays of them, every field has a `schema:"…"` tag, and padding is an explicit `_ [N]byte`
- **Examples that stop**:
  - `testdata/addinit_record_value` `main.go:16:6` — H.AddOrInit needs an integer value, but H holds the record Val
  - `testdata/hash_key_var` `main.go:14:6` — variable k holds the record Key
  - `testdata/kstr_no_field` `main.go:21:10` — Events.OutputKernelStr needs exactly one field tagged `gobpf:"kernelstr"` in the event record Ev, found 0
  - `testdata/kstr_no_status` `main.go:20:10` — Events.OutputKernelStr needs exactly one int64 field tagged `gobpf:"kernelstr_status"` in the event record Ev, found 0
  - `testdata/kstr_not_bytes` `main.go:21:10` — the `gobpf:"kernelstr"` field Name of Ev must be a byte array ([N]uint8 / [N]byte — kernel.read_str writes the string there)
  - `testdata/kstr_status_int32` `main.go:22:10` — the `gobpf:"kernelstr_status"` field St of Ev must be int64 (OutputKernelStr writes the raw status of kernel.read_str there)
  - … and 25 more (`negativeCases`)

## GB017 StatusIgnored

- **Meaning**: an expression statement discarding a map operation's status (int64) (make it explicit with `_ =`)
- **Verdict**: rejected
- **Fix**: use the status (int64 — 0 or a negative errno), or discard it explicitly with `_ = …` (for Output: the result or CountDropsIn)
- **Examples that stop**:
  - `testdata/addinit_ignored` `main.go:16:2` — the status of H.AddOrInit is discarded
  - `testdata/adjust_ignored` `main.go:8:2` — the status of ctx.AdjustHead (0 or a negative errno) is discarded
  - `testdata/hash_status_ignored` `main.go:14:2` — the status of H.Insert is discarded
  - `testdata/kl_pop_discard` `main.go:8:2` — the value and the raw status of Q.Pop are discarded
  - `testdata/kl_push_discard` `main.go:8:2` — the status of Q.Push is discarded
  - `testdata/kr_discard` `main.go:7:2` — the value and the raw status of bpf.KprobeRead are discarded
  - … and 15 more (`negativeCases`)

## GB018 LoopShape

- **Meaning**: outside the bounded loop shape (constant count ≤ 64, nesting 2, things not allowed in the body)
- **Verdict**: rejected
- **Fix**: `for i := range uint32(N)` / `for i := T(0); i < N; i++` (a constant N ≤ 64, nesting 2, product ≤ 64), break / continue as the last statement of an if / Check branch, an unroll estimate of at most 4096 — make the body smaller or lower N
- **Examples that stop**:
  - `testdata/adjust_loop` `main.go:9:7` — ctx.AdjustHead cannot be inside a loop
  - `testdata/cl_depth3` `main.go:25:8` — loops nest 3 deep along Prog → loop 2 → inner → loop 2 → loop 2 — at most 2
  - `testdata/cl_depth3_callee` `main.go:25:8` — loops nest 3 deep along mid → loop 2 → leaf → loop 2 → loop 2 — at most 2
  - `testdata/cl_product72` `main.go:23:8` — the loop counts along Prog → loop 8 → inner → loop 9 multiply to 72 — at most 64
  - `testdata/cl_product_twolevel` `main.go:25:8` — the loop counts along Prog → loop 4 → mid → leaf → loop 32 multiply to 128 — at most 64
  - `testdata/cl_ring_callee_loop` `main.go:17:6` — emit is called inside a loop and reaches the ring buffer (burst → loop 4 → emit → Events.Output)
  - … and 44 more (`negativeCases`)

## GB019 ExportedBPFFunc

- **Meaning**: an exported eBPF side function outside package main (a path to a stub panic when called from another package)
- **Verdict**: rejected
- **Fix**: give eBPF-side functions outside package main lower-case names (attach from a user-space function of the same package)
- **Examples that stop**:
  - `testdata/export_nonmain` `lib.go:7:6` — the eBPF-side function Helper is exported from package lib (not main) — another package could call it and hit the eBPF-only stubs (panic); rename it to helper
  - `testdata/export_nonmain` `lib.go:9:6` — rename it to sample (attach from outside the package through a user-side function of this package)

## GB020 ArrayKeyUnproven

- **Meaning**: an Array variable key that cannot be proven below MaxEntries (Conditional — out of range silently does nothing)
- **Verdict**: conditional
- **Fix**: generation does not stop (Conditional). Prove the key in range by clamping it with `if k >= N { k = N - 1 }` or masking it with `k & (2^j - 1)` — an out-of-range key silently does nothing
- **Example**: `internal/frontend/testdata/keyproof_cond` (Conditional — a golden line of `TestConditionalGolden`)

## GB021 AtomicShape

- **Meaning**: outside the bpf.AtomicAdd use shape (other than &p.F, an array element, an offset not a multiple of the width)
- **Verdict**: rejected
- **Fix**: use the form `bpf.AtomicAdd(&p.F, d)` where p is a checked record pointer and F a 32 / 64-bit integer field (not an array element)
- **Examples that stop**:
  - `testdata/atomic_delta_arith` `main.go:16:23` — reads a field of the same record through the local variable v
  - `testdata/atomic_delta_chain` `main.go:17:23` — reads a field of the same record through the local variable b
  - `testdata/atomic_delta_local` `main.go:16:23` — reads a field of the same record through the local variable v
  - `testdata/atomic_delta_merge` `main.go:19:23` — reads a field of the same record through the local variable v
  - `testdata/atomic_elem` `main.go:18:18` — bpf.AtomicAdd cannot add to an array element
  - `testdata/atomic_int_map` `main.go:18:17` — p points to the integer value of a map — add to it with the map's own method
  - … and 14 more (`negativeCases`)

## GB022 LocRange

- **Meaning**: an op loc outside the range of BTF line_info (column > 1023, line > 2^20 — bpf-mlir refuses it)
- **Fix**: shorten the line (column ≤ 1023, line ≤ 2^20 — the width of BTF line_info) or generate with `go tool gobpf -line-info=off`
- **Example**: `TestLongLineLocRange` (the test creates a temporary package with a 1100-column line — `main.go:13:1125`)

## GB023 TailShape

- **Meaning**: outside the shape of prog_array slot declarations (bpf.TailSlot) and tail calls (TailCall / TailCallIf)
- **Verdict**: rejected
- **Fix**: a slot is `var _ = bpf.TailSlot(&M, constant, Prog)` (an xdp program of the same package), and TailCall / TailCallIf is one top-level statement of an xdp program's body
- **Examples that stop**:
  - `testdata/cx_tail` `main.go:9:2` — TailCall is only available in the program itself, not in a subprogram
  - `testdata/slot_dup` `main.go:9:26` — slot 1 of S is declared twice (first at main.go:8:9)
  - `testdata/slot_funcvar` `main.go:10:29` — must be an xdp program declared in this package, named directly
  - `testdata/slot_in_func` `main.go:11:6` — bpf.TailSlot is a declaration, not a runtime call
  - `testdata/slot_named` `main.go:8:10` — a tail-call slot is declared alone as `var _ = bpf.TailSlot(&M, slot, Program)`
  - `testdata/slot_other_pkg` `main.go:10:29` — must be an xdp program declared in this package, named directly
  - … and 6 more (`negativeCases`)

## GB024 CompileWarning

- **Meaning**: an ebpf-compile warning (rc 0 — a ref.index index reached by a constant and an unknown value on different paths); Conditional
- **Verdict**: conditional
- **Fix**: generation does not stop (Conditional). Follow the ebpf-compile warning and its note location — for example: do not let a constant default flow into a ref.index index (use the index inside the Lookup's checked branch). For a mask-range warning, leave room after the record array up to the next power-of-two element count (`_ [N]byte`)
- **Example**: a constant default that reaches a ref.index index, and the mask range of a trailing [5]uint32 in a record — both appear in the conditional section of the generated file and in the Conditional golden lines

## GB025 PacketWrite

- **Meaning**: outside the XDP packet rewrite shape (writes to a sched_cls window, an old window after a helper, a positive AdjustTail delta)
- **Verdict**: rejected
- **Fix**: packet writes are for xdp programs only. Re-create the window with ctx.Check after an Adjust. The AdjustTail delta is 0 or less
- **Examples that stop**:
  - `testdata/fd_winwrite` `main.go:8:3` — writes the packet of a flow_dissector program
  - `testdata/lwt_winwrite` `main.go:8:3` — writes the packet of a lwt_xmit program
  - `testdata/sc_adjust_window` `main.go:11:15` — window w was checked before ctx.AdjustHead at main.go:10:17
  - `testdata/set_tc` `main.go:9:3` — packet writes are xdp-only
  - `testdata/sockopt_skbwrite` `main.go:8:3` — writes the packet of a cgroup_skb program
  - `testdata/stale_after_adjust` `main.go:10:22` — window w was checked before ctx.AdjustHead at main.go:9:7
  - … and 3 more (`negativeCases`)

## GB026 LockTimerShape

- **Meaning**: outside the spin lock / timer shape (calls, escapes and outer assignments in a WithLock region, starting outside Init == 0, the callback shape, other than xdp)
- **Verdict**: rejected
- **Fix**: inside the WithLock func, only reads and writes of fields of the same p and integer arithmetic. SetCallback / Start go inside `if st := p.T.Init(); st == 0 { … }`. A callback is func(v *V) using only v's fields and bpf.KtimeNs. Lock / timer ops are for xdp programs only
- **Examples that stop**:
  - `testdata/cx_lock` `main.go:16:3` — bpf.WithLock may only be used in the body of an xdp program (bpf-mlir supports spin locks and timers in xdp programs only) — not in a subprogram
  - `testdata/lock_call_in_region` `main.go:22:17` — a call cannot be inside bpf.WithLock's region
  - `testdata/lock_hash` `main.go:19:5` — a record with a lock or a timer may only be the value of a bpf.Array (not the value of a hash)
  - `testdata/lock_if` `main.go:22:4` — *ast.IfStmt cannot be inside bpf.WithLock's region
  - `testdata/lock_kprobe_map` `main.go:20:6` — the kprobe program onPoll uses map Pairs, whose value Pair holds a bpf.SpinLock
  - `testdata/lock_outer_assign` `main.go:23:4` — bpf.WithLock's region cannot assign x, a variable declared outside it
  - … and 16 more (`negativeCases`)

## GB027 KernelTypeShape

- **Meaning**: outside the shape of tp_btf and kernel struct local types (the TPArg shape, kernel type declarations, uses of a kernel pointer other than reads)
- **Verdict**: rejected
- **Fix**: a kernel type has the blank-field marker `_ bpf.Kernel` (tag kernel:"<struct>") and int32 / uint32 fields (each with tag kernel:"<field>"). TPArg is a top-level `p := bpf.TPArg[T](ctx, i)` in a tp_btf body (earlier arguments not read are `_ =`), and p is only used for field reads
- **Examples that stop**:
  - `testdata/fi_dup` `main.go:15:10` — argument 0 of the fentry program f is read as sock here but as i64 at main.go:14:7
  - `testdata/fi_expr` `main.go:9:16` — bpf.FentryArgInt must be a top-level statement of the fentry program body
  - `testdata/fi_idx_12` `main.go:9:37` — the argument index of bpf.FentryArgInt must be a constant 0..11
  - `testdata/fi_idx_var` `main.go:10:37` — the argument index of bpf.FentryArgInt must be a constant 0..11
  - `testdata/fi_in_if` `main.go:10:3` — bpf.FentryArgInt must be a top-level statement of the fentry program body
  - `testdata/fi_sub` `main.go:8:7` — bpf.FentryArgInt may only be used in the body of a fentry program
  - … and 22 more (`negativeCases`)

## GB028 NonAtomicRMW

- **Meaning**: a non-atomic read-modify-write of a shared (not per-CPU) map value (op=, ++, = reading the same path back, Update with a value of the same map)
- **Verdict**: rejected
- **Fix**: reading a shared map value and writing it back (`p.N += d`, `p.N++`, `x := p.N; p.N = x + 1`, `M.Update(k, *p + 1)`) loses counts on several CPUs. For addition use `bpf.AtomicAdd(&p.N, d)` / `M.AtomicAdd(k, d)`, for per-CPU counts a per-CPU map, for updating several fields together `bpf.WithLock(&p.Lock, func() { … })` in xdp. For copies, read and write different maps or keys that are provably different (different constants)
- **Examples that stop**:
  - `testdata/cw_add_assign` `main.go:20:7` — add(…) does p.N += … (main.go:14:2) through its pointer parameter p, and here it is passed a value of the shared map H (key 3)
  - `testdata/cw_caller_read` `main.go:21:7` — set(…) writes its argument 2 to R[0].N (set: p.N = …), and the argument reads R[0].N (through the local variable x) here
  - `testdata/cw_inc` `main.go:20:7` — bump(…) does p.N++ (main.go:14:2) through its pointer parameter p, and here it is passed a value of the shared map R (key 0)
  - `testdata/cw_maybe_inc` `main.go:23:6` — bump(…) does p.N++ (main.go:16:3) through its pointer parameter p, and here it is passed a value of the shared map R (key 2)
  - `testdata/cw_self_local` `main.go:21:7` — inc(…) does p.N = …p.N… (through the local variable n) (main.go:15:2) through its pointer parameter p
  - `testdata/cw_win_rmw` `main.go:25:8` — count(…) does p.Hits++ (main.go:16:3) through its pointer parameter p, and here it is passed a value of the shared map Rules (key 0)
  - … and 24 more (`negativeCases`)

## GB029 BorrowAlias

- **Meaning**: two borrows may point at the same value (same map with keys not shown to be different constants, a Lookup inside a borrow argument of the same type)
- **Verdict**: rejected
- **Fix**: copy the values you need into local variables before the second Lookup (`v := p.F`, close p's branch, then `if q := M.Lookup(k2); q != nil { … }`). To hold two at once, use different maps or different constant keys of the same map (`M.Lookup(0)` and `M.Lookup(1)`)
- **Examples that stop**:
  - `testdata/tb_param_same` `main.go:14:10` — p is a pointer parameter of the same value type — it may point into A
  - `testdata/tb_same_const` `main.go:15:11` — may point to the same value as p (both are values of map A at the same key 1)
  - `testdata/tb_same_var` `main.go:18:11` — A.Lookup(k) inside the checked branch of p may point to the same value as p (both are values of map A and the keys are not both constants)
