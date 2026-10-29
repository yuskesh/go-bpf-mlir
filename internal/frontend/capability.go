package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// A minimal RequirementSet — **the capability table lives in this one file**.
//
// It collects the capabilities that the syntax and calls of each eBPF-side function body need (own) and propagates them callee → caller. A capability the root kind does not provide
// stops with GB011, with the path from the root to the forbidden syntax. Syntax not in the table needs the "unknown" capability (fail closed).
// These are Go-semantics capabilities (at compile time), distinct from kernel capabilities (helpers, map types — the load-time requirements).

// Capability is the name of a capability.
type Capability string

const (
	CapArith         Capability = "arith"
	CapBPFMap        Capability = "bpf.map"
	CapBPFPacket     Capability = "bpf.packet"
	CapBPFCall       Capability = "bpf.call"
	CapGoRuntime     Capability = "go.runtime"
	CapGoHeap        Capability = "go.heap"
	CapGoGoroutine   Capability = "go.goroutine"
	CapGoChan        Capability = "go.chan"
	CapGoDefer       Capability = "go.defer"
	CapGoPanic       Capability = "go.panic"
	CapGoFloat       Capability = "go.float"
	CapGoString      Capability = "go.string"
	CapGoSlice       Capability = "go.slice"
	CapGoMap         Capability = "go.map"
	CapGoInterface   Capability = "go.interface"
	CapUnboundedLoop Capability = "go.unbounded_loop"
	CapUnknown       Capability = "unknown"
)

// provided holds the capabilities each root kind provides.
var provided = map[string]map[Capability]bool{
	"xdp":       {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	"sched_cls": {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true}, // same as XDP (the window is read-only — the API has no writes)
	"fentry":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},                     // no packet window (the context type has no such method)
	"fexit":     {CapArith: true, CapBPFMap: true, CapBPFCall: true},                     // same as fentry
	"kprobe":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},                     // same as fentry (arguments via KprobeArg)
	"uprobe":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},                     // same as kprobe
	"tp_btf":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},                     // tracing, same as fentry
	// tracing, same as fentry
	"tracepoint": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"raw_tp":     {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"kretprobe":  {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"uretprobe":  {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// cgroup_skb has the packet window (read-only)
	"socket_filter":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"cgroup_skb":       {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	"cgroup_sock":      {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"cgroup_sock_addr": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"sock_ops":         {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"cgroup_device":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"cgroup_sysctl":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// sk_lookup reads the ctx and uses maps
	"sk_lookup": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// the three lwt kinds read the packet window and len
	"lwt_in":   {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	"lwt_out":  {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	"lwt_xmit": {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	// lwt_seg6local uses ctx fields and maps (no packet window)
	"lwt_seg6local": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// netfilter reads state / skb kfields and uses maps
	"netfilter": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// flow_dissector has the packet window and flow_keys
	"flow_dissector": {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	// sk_reuseport reads the ctx and uses maps and sk.select_reuseport
	"sk_reuseport": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// cgroup_sockopt has the optval window (packet ops)
	"cgroup_sockopt": {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
	// tracing, same as fentry (arguments via LSMArg / LSMArgInt, the result is an LSMRet constant)
	"lsm":   {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"lsm_s": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// fmod_ret is tracing, same as fentry (arguments via FmodRetArgInt, the result is a computed FmodRet)
	"fmod_ret": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// raw_tp_writable is the same as raw_tp (plus the writable buffer's Buffer / SetBuffer)
	"raw_tp_writable": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// kprobe_session is the same as fsession (session ops, no arguments)
	"kprobe_session": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// syscall reads the ctx and uses maps (test run only)
	"syscall": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// ext uses the replaced function's arguments (ExtArg) and maps
	"ext": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// struct_ops (tcp_congestion_ops members) uses maps and arithmetic
	"struct_ops": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// lsm_cgroup (no arguments, the verdict is CgroupAction)
	"lsm_cgroup": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// fsession (session ops, no arguments, no result)
	"fsession": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// iter (bpf_iter_meta reads and seq.write)
	"iter": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// tracing, same as fentry (the ctx has only SamplePeriod)
	"perf_event": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// tracing, same as kprobe (arguments via KsyscallArg)
	"ksyscall": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// tracing, same as kprobe / kretprobe
	"kprobe_multi":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"kretprobe_multi": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// tracing, same as uprobe / uretprobe
	"uprobe_multi":    {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	"uretprobe_multi": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// tracing, same as uprobe (arguments via USDTArg)
	"usdt": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// sk_skb uses ctx fields (len, local_port), maps and sk.redirect (no packet window — bpf-mlir's kind row "-")
	"sk_skb": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// sk_msg uses ctx fields, maps and msg.redirect (the data / data_end window is out of scope)
	"sk_msg": {CapArith: true, CapBPFMap: true, CapBPFCall: true},
	// sched_act is the same as sched_cls (packet window reads)
	"sched_act": {CapArith: true, CapBPFMap: true, CapBPFPacket: true, CapBPFCall: true},
}

// requirement is the first reason for one capability.
type requirement struct {
	pos    token.Pos
	reason string // for example "call to fmt.Println"
}

// own returns the capabilities a function body needs directly (the reason is the first position).
func (a *analyzer) ownRequirements(fd *ast.FuncDecl) map[Capability]requirement {
	req := map[Capability]requirement{}
	add := func(c Capability, p token.Pos, format string, args ...any) {
		if _, ok := req[c]; !ok {
			req[c] = requirement{p, fmt.Sprintf(format, args...)}
		}
	}
	typeCap := func(t types.Type) (Capability, bool) {
		switch u := t.Underlying().(type) {
		case *types.Basic:
			switch {
			case u.Info()&types.IsFloat != 0 || u.Info()&types.IsComplex != 0:
				return CapGoFloat, true
			case u.Info()&types.IsString != 0:
				return CapGoString, true
			}
		case *types.Slice, *types.Array:
			if _, isArr := u.(*types.Array); isArr {
				return "", false // fixed-size arrays are handled as record fields (lowering checks the shape)
			}
			return CapGoSlice, true
		case *types.Map:
			return CapGoMap, true
		case *types.Chan:
			return CapGoChan, true
		case *types.Interface:
			return CapGoInterface, true
		case *types.Signature:
			return CapUnknown, true
		}
		return "", false
	}
	// The callee expressions (call.Fun and selector names) have function types, but callRequirement checks them as calls — exclude them from the type check.
	recordLits := a.recordLiteralArgs(fd.Body) // composite literals in record value argument positions (lowering turns them into record.make)
	atomicAddrs := a.atomicAddrArgs(fd.Body)   // the `&…` first argument of bpf.AtomicAdd (lowering checks the shape with GB021)
	lockLits := a.withLockLits(fd.Body)        // the func literal second argument of bpf.WithLock (the checks below and lowering's GB026 look at its body)
	funNodes := map[ast.Node]bool{}
	sysctlLits := map[ast.Node]bool{} // the string constant argument of ctx.SetNewValue (lowering makes it a literal attribute — no string value is built)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			funNodes[c.Fun] = true
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				funNodes[sel.Sel] = true
				if e, known := lookupAPI(a.info.Uses[sel.Sel]); known && e.op == "sysctl_set" && len(c.Args) == 1 {
					if tv := a.info.Types[c.Args[0]]; tv.Value != nil {
						ast.Inspect(c.Args[0], func(m ast.Node) bool {
							if x, ok := m.(ast.Expr); ok {
								sysctlLits[x] = true
							}
							return true
						})
					}
				}
				// A timer callback function value (`p.T.SetCallback(onFire)`, the shape is lowering's GB026).
				// The same for the user_ringbuf drain callback (`In.Drain(onReq)`, the shape is lowering's GB026).
				if o := a.info.Uses[sel.Sel]; o != nil && o.Pkg() != nil && o.Pkg().Path() == bpfPkg && (o.Name() == "SetCallback" || o.Name() == "Drain") && len(c.Args) == 1 {
					funNodes[ast.Unparen(c.Args[0])] = true
				}
			}
			if ie, ok := c.Fun.(*ast.IndexExpr); ok { // a generic function with explicit type arguments (bpf.KprobeArg[T])
				funNodes[ie.X] = true
				if sel, ok := ie.X.(*ast.SelectorExpr); ok {
					funNodes[sel.Sel] = true
				}
			}
		}
		switch n := n.(type) {
		case *ast.GoStmt:
			add(CapGoGoroutine, n.Pos(), "go statement")
		case *ast.DeferStmt:
			add(CapGoDefer, n.Pos(), "defer statement")
		case *ast.SendStmt, *ast.SelectStmt:
			add(CapGoChan, n.Pos(), "channel operation")
		case *ast.ForStmt, *ast.RangeStmt:
			// Bounded loop shapes (for i := range N / for i := T(0); i < …; i++) are within capabilities — lowering checks count, type and nesting rules with GB018.
			if !a.boundedLoopForm(n.(ast.Stmt)) {
				add(CapUnboundedLoop, n.Pos(), "loop (only `for i := range N` and `for i := T(0); i < N; i++` with a constant N ≤ 64 are bounded)")
			}
		case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.LabeledStmt:
			add(CapUnknown, n.Pos(), "%s is not in the capability table", strings.TrimPrefix(fmt.Sprintf("%T", n), "*ast."))
		case *ast.BranchStmt:
			if n.Label != nil || (n.Tok != token.BREAK && n.Tok != token.CONTINUE) {
				add(CapUnknown, n.Pos(), "%s is not in the capability table", n.Tok)
			}
		case *ast.FuncLit:
			if lockLits[n] {
				return true // the body of a closed region
			}
			add(CapUnknown, n.Pos(), "function literal (closure) is not in the capability table")
			return false
		case *ast.UnaryExpr:
			if n.Op == token.AND && !atomicAddrs[n] {
				add(CapGoHeap, n.Pos(), "taking an address (&)")
			}
			if n.Op == token.ARROW {
				add(CapGoChan, n.Pos(), "channel receive")
			}
		case *ast.CompositeLit:
			if !recordLits[n] {
				add(CapGoHeap, n.Pos(), "composite literal (the only composite literal allowed is a record literal as the value of Update)")
			}
		case *ast.CallExpr:
			a.callRequirement(n, add)
		case ast.Expr:
			if funNodes[n] || sysctlLits[n] {
				return true
			}
			if tv, ok := a.info.Types[n]; ok && tv.Type != nil && !tv.IsType() {
				if c, ok := typeCap(tv.Type); ok {
					add(c, n.Pos(), "value of type %s", tv.Type)
				}
			}
		}
		return true
	})
	return req
}

func (a *analyzer) callRequirement(call *ast.CallExpr, add func(Capability, token.Pos, string, ...any)) {
	if a.info.Types[call.Fun].IsType() {
		return // a conversion (the type is checked in the ast.Expr branch)
	}
	var obj types.Object
	switch f := call.Fun.(type) {
	case *ast.Ident:
		obj = a.info.Uses[f]
	case *ast.SelectorExpr:
		obj = a.info.Uses[f.Sel]
	case *ast.IndexExpr, *ast.IndexListExpr: // a generic function with explicit type arguments (bpf.KprobeArg[T])
		var x ast.Expr
		if ie, ok := f.(*ast.IndexExpr); ok {
			x = ie.X
		} else {
			x = f.(*ast.IndexListExpr).X
		}
		switch g := x.(type) {
		case *ast.Ident:
			obj = a.info.Uses[g]
		case *ast.SelectorExpr:
			obj = a.info.Uses[g.Sel]
		default:
			add(CapUnknown, call.Pos(), "call through a function value")
			return
		}
	case *ast.ParenExpr:
		add(CapUnknown, call.Pos(), "call through an expression")
		return
	default:
		add(CapUnknown, call.Pos(), "call through a function value")
		return
	}
	switch o := obj.(type) {
	case *types.Builtin:
		switch o.Name() {
		case "len", "cap":
			// len / cap of an array is a Go constant (`i < uint32(len(p.Arr))`). If not constant (slices etc.) it is runtime.
			if a.info.Types[call].Value == nil {
				add(CapGoRuntime, call.Pos(), "builtin %s of a non-array", o.Name())
			}
		case "new", "make", "append":
			add(CapGoHeap, call.Pos(), "builtin %s", o.Name())
		case "panic", "recover":
			add(CapGoPanic, call.Pos(), "builtin %s", o.Name())
		case "print", "println":
			add(CapGoRuntime, call.Pos(), "builtin %s", o.Name())
		default:
			add(CapUnknown, call.Pos(), "builtin %s is not in the capability table", o.Name())
		}
	case *types.Func:
		if inAPIPackage(o) {
			if e, ok := lookupAPI(o); ok && e.side != sideUser {
				if _, isStatus := statusOps[e.op]; isStatus || e.op == "lookup" || e.op == "update" || e.op == "atomic_add" || e.op == "output" || e.op == "count_drops" || e.op == "tail_call" || e.op == "tail_call_if" || e.op == "global_load" || e.op == "global_add" || e.op == "lpm_lookup" || e.op == "redirect_map" || e.op == "redirect_map_if" || e.op == "output_str" || e.op == "output_str_discard" || e.op == "output_kernel_str" || e.op == "stack_id" || e.op == "stack_id_reuse" || e.op == "stack_user_id" || e.op == "stack_user_id_reuse" || e.op == "perf_output" || e.op == "keyless_pop" || e.op == "keyless_peek" || e.op == "sk_assign" {
					add(CapBPFMap, call.Pos(), "map operation %s", o.Name())
				}
				if strings.HasPrefix(e.op, "packet") {
					add(CapBPFPacket, call.Pos(), "packet access %s", o.Name())
				}
			}
			return // checkEBPFSide stops calls not in the table or on the user-space side with GB002 / GB003
		}
		if o.Pkg() == a.pkg.Types {
			if sig := o.Type().(*types.Signature); sig.Recv() == nil {
				add(CapBPFCall, call.Pos(), "call to %s", o.Name())
				return // callee capabilities come through propagation
			}
		}
		if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
			if _, isIface := sig.Recv().Type().Underlying().(*types.Interface); isIface {
				add(CapGoInterface, call.Pos(), "interface method call %s", o.Name())
				return
			}
		}
		add(CapGoRuntime, call.Pos(), "call to %s", qualifiedName(o))
	default:
		add(CapUnknown, call.Pos(), "call target is not in the capability table")
	}
}

// checkCapabilities collects the capabilities each root needs (own ∪ callees — with paths) and stops capabilities not provided with GB011.
// It returns the set of functions that themselves need a capability not provided (they are not lowered — so the same syntax is not reported twice). It writes each eBPF-side node's requires to domain-graph.
func (a *analyzer) checkCapabilities() map[FuncKey]bool {
	// domain-graph node requires (the transitive union per function — computed on the summaries).
	byName := map[string]FuncKey{}
	for k, s := range a.summaries {
		byName[s.Name] = k
	}
	for i, n := range a.graph.Nodes {
		if n.Domain != "ebpf" {
			continue
		}
		var caps []string
		for c := range a.transitiveRequires(byName[n.Func]) {
			caps = append(caps, string(c))
		}
		sort.Strings(caps)
		if caps == nil {
			caps = []string{}
		}
		a.graph.Nodes[i].Requires = caps
	}
	// Per root, in the closure's BFS order, report the first source of each capability not provided (the path is the BFS tree — shortest, deterministic with callees in reference order).
	bad := map[FuncKey]bool{}
	for _, p := range a.programs {
		c := a.closures[p]
		give := provided[c.Entry.ProgramType]
		reported := map[Capability]bool{}
		for _, k := range c.Funcs {
			s := a.summaries[k]
			if s == nil {
				continue
			}
			for _, cap := range sortedCaps(s.Own) {
				if give[cap] {
					continue
				}
				bad[k] = true // report once per capability; skip lowering for every function that has a capability not provided
				if reported[cap] {
					continue
				}
				reported[cap] = true
				r := s.Own[cap]
				verdict := Rejected
				if cap == CapUnknown {
					verdict = Unknown
				}
				path := append(a.pathTo(c, k), r.reason)
				a.report(verdict, GB011CapabilityNotProvided, r.pos, path,
					"%s needs capability %q (%s), which a %s program does not provide", s.Name, cap, r.reason, c.Entry.ProgramType)
			}
		}
	}
	return bad
}

// atomicAddrArgs returns the `&x` first arguments of `bpf.AtomicAdd(&x, d)` in body (taking an address is not the heap capability; it is accepted only in the
// bpf.AtomicAdd argument position — lowering limits it to `&p.F`, a checked record field).
func (a *analyzer) atomicAddrArgs(body ast.Node) map[*ast.UnaryExpr]bool {
	out := map[*ast.UnaryExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		fun := ast.Unparen(call.Fun)
		switch f := fun.(type) {
		case *ast.IndexExpr:
			fun = f.X
		case *ast.IndexListExpr:
			fun = f.X
		}
		sel, ok := fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		obj := a.info.Uses[sel.Sel]
		if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != bpfPkg || (obj.Name() != "AtomicAdd" && obj.Name() != "WithLock") {
			return true
		}
		if u, isU := ast.Unparen(call.Args[0]).(*ast.UnaryExpr); isU && u.Op == token.AND {
			out[u] = true
		}
		return true
	})
	return out
}

// withLockLits returns the func literal second arguments of bpf.WithLock (a FuncLit exception outside the capability table; the body shape is lowering's GB026).
func (a *analyzer) withLockLits(body ast.Node) map[*ast.FuncLit]bool {
	out := map[*ast.FuncLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if obj := a.info.Uses[sel.Sel]; obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != bpfPkg || obj.Name() != "WithLock" {
			return true
		}
		if fl, ok := ast.Unparen(call.Args[1]).(*ast.FuncLit); ok {
			out[fl] = true
		}
		return true
	})
	return out
}
