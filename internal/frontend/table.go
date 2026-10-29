package frontend

import (
	"go/types"
)

// The table of accepted identifiers — **in one place**. An identifier of the bpf / gobpf packages that is not here
// stops as Unknown (GB002) on either side (fail closed).

const (
	bpfPkg   = "github.com/yuskesh/go-bpf-mlir/bpf"
	gobpfPkg = "github.com/yuskesh/go-bpf-mlir/gobpf"
)

// side is the side allowed to use the identifier.
type side int

const (
	sideBoth side = iota
	sideEBPF
	sideUser
)

type apiEntry struct {
	side side
	op   string // the kind of eBPF side lowering ("" for values and types only)
}

// apiTable is keyed by qualifiedName (package path + "." + [type "."] name).
var apiTable = map[string]apiEntry{
	// types
	bpfPkg + ".XDPContext":       {sideBoth, ""},
	bpfPkg + ".FentryContext":    {sideBoth, ""}, // fentry
	bpfPkg + ".FexitContext":     {sideBoth, ""}, // fexit
	bpfPkg + ".FexitContext.Ret": {sideEBPF, "fexit_ret"},
	bpfPkg + ".CurrentPidTgid":   {sideEBPF, "pid_tgid"},
	bpfPkg + ".KtimeNs":          {sideEBPF, "ktime"},
	bpfPkg + ".CurrentComm":      {sideEBPF, "current_comm"},
	bpfPkg + ".XDPAction":        {sideBoth, ""},
	bpfPkg + ".Array":            {sideBoth, ""},
	bpfPkg + ".RingBuf":          {sideBoth, ""},
	bpfPkg + ".Key32":            {sideBoth, ""},
	// map declaration fields
	bpfPkg + ".Array.MaxEntries":   {sideUser, ""}, // only in the declaration's composite literal (a package-level var on the user-space side)
	bpfPkg + ".RingBuf.MaxEntries": {sideUser, ""},
	// verdict constants
	bpfPkg + ".XDPAborted": {sideBoth, "verdict"},
	bpfPkg + ".XDPDrop":    {sideBoth, "verdict"},
	bpfPkg + ".XDPPass":    {sideBoth, "verdict"},
	bpfPkg + ".XDPTx":      {sideBoth, "verdict"},
	// eBPF-side-only methods
	bpfPkg + ".Array.Lookup":    {sideEBPF, "lookup"},
	bpfPkg + ".Array.Update":    {sideEBPF, "update"},
	bpfPkg + ".Array.AtomicAdd": {sideEBPF, "atomic_add"},
	bpfPkg + ".AtomicAdd":       {sideEBPF, "field_atomic_add"}, // bpf.AtomicAdd(&p.F, d) — a record field
	bpfPkg + ".RingBuf.Output":  {sideEBPF, "output"},
	bpfPkg + ".CountDropsIn":    {sideEBPF, "count_drops"},
	bpfPkg + ".DropCounter":     {sideBoth, ""},
	// packet
	bpfPkg + ".Window":           {sideBoth, ""},
	bpfPkg + ".XDPContext.Check": {sideEBPF, "packet_check"},
	bpfPkg + ".Window.U8":        {sideEBPF, "packet_load"},
	bpfPkg + ".Window.BE16":      {sideEBPF, "packet_load"},
	bpfPkg + ".Window.BE32":      {sideEBPF, "packet_load"},
	bpfPkg + ".Window.BE64":      {sideEBPF, "packet_load"},
	bpfPkg + ".Window.LE16":      {sideEBPF, "packet_load"},
	bpfPkg + ".Window.LE32":      {sideEBPF, "packet_load"},
	bpfPkg + ".Window.LE64":      {sideEBPF, "packet_load"},
	// user-space-side-only methods
	bpfPkg + ".Array.Get": {sideUser, ""},
	bpfPkg + ".Array.Put": {sideUser, ""},
}

// verdictNames maps an XDPAction value to its ebpf.verdict spelling.
var verdictNames = map[uint64]string{0: "aborted", 1: "drop", 2: "pass", 3: "tx"}

// qualifiedName returns the table key of obj. Methods and fields include the receiver type name (a generic instance maps back to its original declaration).
func qualifiedName(obj types.Object) string {
	if obj.Pkg() == nil {
		return obj.Name()
	}
	switch o := obj.(type) {
	case *types.Func:
		o = o.Origin()
		if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
			return o.Pkg().Path() + "." + recvTypeName(sig.Recv().Type()) + "." + o.Name()
		}
		return o.Pkg().Path() + "." + o.Name()
	case *types.Var:
		if o.IsField() {
			return o.Pkg().Path() + "." + fieldOwner(o) + "." + o.Name()
		}
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Origin().Obj().Name()
	}
	return t.String()
}

// fieldOwner returns the name of the bpf type that has the field (only Array in the first version).
func fieldOwner(f *types.Var) string {
	scope := f.Pkg().Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i) == f.Origin() {
				return name
			}
		}
	}
	return "?"
}

// inAPIPackage reports whether obj belongs to the bpf or gobpf package.
func inAPIPackage(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	p := obj.Pkg().Path()
	return p == bpfPkg || p == gobpfPkg
}

// lookupAPI looks up the table. Every identifier of the gobpf package is on the user-space side (runtime).
func lookupAPI(obj types.Object) (apiEntry, bool) {
	if obj.Pkg() != nil && obj.Pkg().Path() == gobpfPkg {
		return apiEntry{side: sideUser}, true
	}
	e, ok := apiTable[qualifiedName(obj)]
	return e, ok
}

// The table for hash family maps. Hash and LRUHash have the same operations.
func init() {
	for _, t := range []string{"Hash", "LRUHash"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Lookup"] = apiEntry{sideEBPF, "lookup"}
		apiTable[p+".Update"] = apiEntry{sideEBPF, "try_update_any"}
		apiTable[p+".Insert"] = apiEntry{sideEBPF, "try_update_noexist"}
		apiTable[p+".Replace"] = apiEntry{sideEBPF, "try_update_exist"}
		apiTable[p+".Delete"] = apiEntry{sideEBPF, "try_delete"}
		apiTable[p+".AddOrInit"] = apiEntry{sideEBPF, "add_or_init"}
		apiTable[p+".Get"] = apiEntry{sideUser, ""}
		apiTable[p+".Put"] = apiEntry{sideUser, ""}
		apiTable[p+".Remove"] = apiEntry{sideUser, ""}
		apiTable[p+".Iterate"] = apiEntry{sideUser, ""}
	}
	for _, n := range []string{"Iterator", "Iterator.Next", "Iterator.Key", "Iterator.Value", "Iterator.Err"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideUser, ""}
	}
	for _, n := range []string{"ENOENT", "E2BIG", "ENOMEM", "EEXIST"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideBoth, ""}
	}
}

// statusOps are the map operations returning a status (int64) (an expression statement discarding it is GB017).
var statusOps = map[string]string{
	"try_update_any": "any", "try_update_noexist": "noexist", "try_update_exist": "exist", "try_delete": "", "add_or_init": "",
	"storage_delete": "",                                     // local storage
	"keyless_push":   "", "bloom_push": "", "bloom_peek": "", // keyless maps
	"sock_insert":      "", // sock.map_update of sock_ops
	"reuseport_select": "", // sk.select_reuseport of sk_reuseport
	"cgarr_task":       "", // task.under_cgroup of cgroup_array
	"cgarr_skb":        "", // skb.under_cgroup of cgroup_array
}

// cgroup_array. The eBPF side has only TaskUnder / SkbUnder; user space Sets (a cgroup dir fd) / Clears a slot.
func init() {
	p := bpfPkg + ".CgroupArray"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".TaskUnder"] = apiEntry{sideEBPF, "cgarr_task"}
	apiTable[p+".SkbUnder"] = apiEntry{sideEBPF, "cgarr_skb"}
	for _, n := range []string{"Set", "Clear", "GobpfTypes", "GobpfMapKind"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	apiTable[bpfPkg+".TCContext"] = apiEntry{sideBoth, ""}
}

// reuseport_sockarray and sk_reuseport. The eBPF side has only Select; user space Sets entries (a read returns the socket cookie).
func init() {
	p := bpfPkg + ".ReuseportSockArray"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".Select"] = apiEntry{sideEBPF, "reuseport_select"}
	for _, n := range []string{"Set", "Cookie", "Remove", "GobpfTypes", "GobpfMapKind"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
}

// Keyless maps. The eBPF side has Push (status) and Pop / Peek (value and status — the `v, st :=` shape), bloom has Push / Peek (status),
// and user space has Put / Take / Get (bloom has Put / Has).
func init() {
	for _, t := range []string{"Queue", "Stack"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Push"] = apiEntry{sideEBPF, "keyless_push"}
		apiTable[p+".Pop"] = apiEntry{sideEBPF, "keyless_pop"}
		apiTable[p+".Peek"] = apiEntry{sideEBPF, "keyless_peek"}
		for _, n := range []string{"Put", "Take", "Get", "GobpfTypes", "GobpfMapKind"} {
			apiTable[p+"."+n] = apiEntry{sideUser, ""}
		}
	}
	p := bpfPkg + ".BloomFilter"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".ZeroSeed"] = apiEntry{sideUser, ""}
	apiTable[p+".Push"] = apiEntry{sideEBPF, "bloom_push"}
	apiTable[p+".Peek"] = apiEntry{sideEBPF, "bloom_peek"}
	for _, n := range []string{"Put", "Has", "GobpfTypes", "GobpfMapKind", "GobpfMapFlags"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	apiTable[bpfPkg+".PushFlag"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".PushAny"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".PushExist"] = apiEntry{sideBoth, ""}
}

// map-in-map. The eBPF side has the outer Lookup (two levels of `if m := O.Lookup(k); m != nil`) and the inner Lookup / Update / AtomicAdd (the same ops as Array);
// user space has NewInner / Set / Remove and the inner Get / Put / Close.
func init() {
	for _, t := range []string{"ArrayOfMaps", "HashOfMaps"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Inner"] = apiEntry{sideUser, ""}
		apiTable[p+".Lookup"] = apiEntry{sideEBPF, "outer_lookup"}
		for _, n := range []string{"NewInner", "Set", "Remove", "GobpfTypes", "GobpfMapKind", "GobpfInner"} {
			apiTable[p+"."+n] = apiEntry{sideUser, ""}
		}
	}
	p := bpfPkg + ".InnerMap"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".Lookup"] = apiEntry{sideEBPF, "lookup"}
	apiTable[p+".Update"] = apiEntry{sideEBPF, "update"}
	apiTable[p+".AtomicAdd"] = apiEntry{sideEBPF, "atomic_add"}
	for _, n := range []string{"Get", "Put", "Close"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	for _, n := range []string{"InnerSpec", "InnerSpec.Kind", "InnerSpec.MaxEntries", "InnerKind", "InnerArray", "InnerHash", "InnerLRUHash"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideBoth, ""}
	}
}

// Local storage maps. The eBPF side has Get (a borrow — the if shape of Lookup) and Delete (status); user space has GetFD / DeleteFD by fd.
func init() {
	for t := range storageKinds {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".Get"] = apiEntry{sideEBPF, "storage_get"}
		apiTable[p+".Delete"] = apiEntry{sideEBPF, "storage_delete"}
		for _, u := range []string{"GetFD", "DeleteFD", "GobpfTypes", "GobpfMapKind", "GobpfMaxEntries", "GobpfMapFlags"} {
			apiTable[p+"."+u] = apiEntry{sideUser, ""}
		}
	}
	apiTable[bpfPkg+".StorageFlag"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".Create"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".NoCreate"] = apiEntry{sideBoth, ""}
}

// Marker methods — an internal API of the gobpf runtime. Not stopped on the user side (harmless); GB003 on the eBPF side.
func init() {
	for _, t := range []string{"Array", "Hash", "LRUHash", "RingBuf"} {
		apiTable[bpfPkg+"."+t+".GobpfTypes"] = apiEntry{sideUser, ""}
	}
}

// Per-CPU maps. PerCPUArray has the same eBPF side operations as Array, the hash family the same as Hash. User space reads and writes per CPU.
func init() {
	p := bpfPkg + ".PerCPUArray"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".Lookup"] = apiEntry{sideEBPF, "lookup"}
	apiTable[p+".Update"] = apiEntry{sideEBPF, "update"}
	apiTable[p+".AtomicAdd"] = apiEntry{sideEBPF, "atomic_add"}
	for _, n := range []string{"GetPerCPU", "PutPerCPU", "GobpfTypes"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	for _, t := range []string{"PerCPUHash", "LRUPerCPUHash"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Lookup"] = apiEntry{sideEBPF, "lookup"}
		apiTable[p+".Update"] = apiEntry{sideEBPF, "try_update_any"}
		apiTable[p+".Insert"] = apiEntry{sideEBPF, "try_update_noexist"}
		apiTable[p+".Replace"] = apiEntry{sideEBPF, "try_update_exist"}
		apiTable[p+".Delete"] = apiEntry{sideEBPF, "try_delete"}
		for _, n := range []string{"GetPerCPU", "PutPerCPU", "Remove", "Iterate", "GobpfTypes"} {
			apiTable[p+"."+n] = apiEntry{sideUser, ""}
		}
	}
	apiTable[bpfPkg+".SumPerCPU"] = apiEntry{sideUser, ""}
}

// The marker method GobpfMapKind (an internal API of the gobpf runtime).
func init() {
	for _, t := range []string{"Array", "PerCPUArray", "Hash", "LRUHash", "PerCPUHash", "LRUPerCPUHash", "RingBuf"} {
		apiTable[bpfPkg+"."+t+".GobpfMapKind"] = apiEntry{sideUser, ""}
	}
}

// sched_cls (tcx).
func init() {
	for _, t := range []string{"TCIngressContext", "TCEgressContext"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".Check"] = apiEntry{sideEBPF, "packet_check"}
		apiTable[p+".Redirect"] = apiEntry{sideEBPF, "redirect"}
		apiTable[p+".RedirectIf"] = apiEntry{sideEBPF, "redirect_if"}
	}
	apiTable[bpfPkg+".TCAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".TCPass"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".TCDrop"] = apiEntry{sideBoth, "verdict"}
}

// prog_array and tail calls. TailSlot is a package-level declaration (user-space side — the shape is in tail.go).
func init() {
	p := bpfPkg + ".ProgArray"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".TailCall"] = apiEntry{sideEBPF, "tail_call"}
	apiTable[p+".TailCallIf"] = apiEntry{sideEBPF, "tail_call_if"}
	apiTable[p+".GobpfTypes"] = apiEntry{sideUser, ""}
	apiTable[p+".GobpfMapKind"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".TailSlot"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Slot"] = apiEntry{sideUser, ""}
}

// XDP packet rewriting.
func init() {
	for _, n := range []string{"SetU8", "SetBE16", "SetBE32", "SetBE64", "SetLE16", "SetLE32", "SetLE64"} {
		apiTable[bpfPkg+".Window."+n] = apiEntry{sideEBPF, "packet_store"}
	}
	apiTable[bpfPkg+".XDPContext.AdjustHead"] = apiEntry{sideEBPF, "adjust_head"}
	apiTable[bpfPkg+".XDPContext.AdjustTail"] = apiEntry{sideEBPF, "adjust_tail"}
}

// Global variables. Config is .rodata (Set before Load), Global is .bss (atomic Add).
func init() {
	for _, n := range []string{"Config", "Global", "ConfigInt", "GlobalInt"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideBoth, ""}
	}
	apiTable[bpfPkg+".Config.Optional"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Config.Value"] = apiEntry{sideEBPF, "global_load"}
	apiTable[bpfPkg+".Config.Set"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Config.Get"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Config.GobpfGlobal"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Global.Add"] = apiEntry{sideEBPF, "global_add"}
	apiTable[bpfPkg+".Global.Load"] = apiEntry{sideEBPF, "global_load"}
	apiTable[bpfPkg+".Global.Get"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".Global.GobpfGlobal"] = apiEntry{sideUser, ""}
}

// lpm_trie. The eBPF side has only Lookup (value and ok); user space builds the table with netip.Prefix. LPMKey4 is an internal type of the gobpf runtime.
func init() {
	p := bpfPkg + ".LPMTrie4"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
	apiTable[p+".Lookup"] = apiEntry{sideEBPF, "lpm_lookup"}
	for _, n := range []string{"Put", "Remove", "Match", "Iterate", "GobpfTypes", "GobpfMapKind"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	for _, n := range []string{"LPMValue", "LPMKey4", "LPMIterator", "LPMIterator.Next", "LPMIterator.Prefix", "LPMIterator.Value", "LPMIterator.Err"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideUser, ""}
	}
	apiTable[bpfPkg+".LPMValue"] = apiEntry{sideBoth, ""}
}

// kprobe. KprobeArg is a generic eBPF side function (the register of argument n).
func init() {
	apiTable[bpfPkg+".KprobeContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KprobeInt"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KprobeValue"] = apiEntry{sideBoth, ""} // KprobeInt and uintptr
	apiTable[bpfPkg+".KprobeArg"] = apiEntry{sideEBPF, "kprobe_arg"}
	apiTable[bpfPkg+".KprobeRead"] = apiEntry{sideEBPF, "kprobe_read"} // a read through a pointer argument
}

// devmap and redirect_map. The eBPF side has only the terminal Redirect / RedirectIf; user space Sets entries.
func init() {
	for _, t := range []string{"DevMap", "CPUMap", "DevMapHash", "XSKMap"} { // CPUMap, DevMapHash and XSKMap too
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Redirect"] = apiEntry{sideEBPF, "redirect_map"}
		apiTable[p+".RedirectIf"] = apiEntry{sideEBPF, "redirect_map_if"}
		for _, n := range []string{"Set", "Remove", "GobpfTypes", "GobpfMapKind"} {
			apiTable[p+"."+n] = apiEntry{sideUser, ""}
		}
	}
	apiTable[bpfPkg+".DevMap.Get"] = apiEntry{sideUser, ""} // only DevMap has Get
}

// uprobe. UprobeArg / UprobeStr are a generic / plain eBPF side function, OutputStr is a RingBuf method (a user string into an event field).
func init() {
	apiTable[bpfPkg+".UprobeContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".UserStr"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".UprobeArg"] = apiEntry{sideEBPF, "uprobe_arg"}
	apiTable[bpfPkg+".UprobeStr"] = apiEntry{sideEBPF, "uprobe_str"}
	apiTable[bpfPkg+".RingBuf.OutputStr"] = apiEntry{sideEBPF, "output_str"}
	apiTable[bpfPkg+".RingBuf.OutputStrOrDiscard"] = apiEntry{sideEBPF, "output_str_discard"} // a failed read (st < 0) discards
}

// Kernel char * strings (bpf-mlir's kernel.read_str and the schema's strptr). KernelStr is a local type field type,
// OutputKernelStr a RingBuf method (copies what a KernelStr field of a checked kernel pointer points to into an event field).
func init() {
	apiTable[bpfPkg+".KernelStr"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".RingBuf.OutputKernelStr"] = apiEntry{sideEBPF, "output_kernel_str"}
}

// Stack traces and perf events. The eBPF side has only KernelID / KernelIDReuse / Output in fentry; the user side has Get / Delete (stack) and the reader (gobpf).
func init() {
	s := bpfPkg + ".StackTrace"
	apiTable[s] = apiEntry{sideBoth, ""}
	apiTable[s+".KernelID"] = apiEntry{sideEBPF, "stack_id"}
	apiTable[s+".KernelIDReuse"] = apiEntry{sideEBPF, "stack_id_reuse"}
	apiTable[s+".UserID"] = apiEntry{sideEBPF, "stack_user_id"}            // the user stack
	apiTable[s+".UserIDReuse"] = apiEntry{sideEBPF, "stack_user_id_reuse"} // the user stack
	b := bpfPkg + ".StackBuildID"                                          // build id stacks
	apiTable[b] = apiEntry{sideBoth, ""}
	apiTable[b+".UserID"] = apiEntry{sideEBPF, "stack_user_id"}
	apiTable[b+".UserIDReuse"] = apiEntry{sideEBPF, "stack_user_id_reuse"}
	for _, n := range []string{"MaxEntries", "Depth", "Get", "Delete", "GobpfTypes", "GobpfMapKind", "GobpfMapFlags"} {
		apiTable[b+"."+n] = apiEntry{sideUser, ""}
	}
	apiTable[bpfPkg+".StackContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".StackBuildIDEntry"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".StackFrame"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".StackDepth"] = apiEntry{sideUser, ""}
	// the status type and values of a build id stack element (aliases of bindrt — user space only)
	apiTable[bpfPkg+".StackFrameStatus"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".StackFrameEmpty"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".StackFrameValid"] = apiEntry{sideUser, ""}
	apiTable[bpfPkg+".StackFrameIP"] = apiEntry{sideUser, ""}
	for _, n := range []string{"MaxEntries", "Depth", "Get", "Delete", "GobpfTypes", "GobpfMapKind"} {
		apiTable[s+"."+n] = apiEntry{sideUser, ""}
	}
	p := bpfPkg + ".PerfEventArray"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".Output"] = apiEntry{sideEBPF, "perf_output"}
	for _, n := range []string{"GobpfTypes", "GobpfEvent", "GobpfMapKind", "GobpfMaxEntries"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
}

// Spin locks and timers. SpinLock / Timer are record field types; WithLock and the Timer methods are eBPF side only.
func init() {
	apiTable[bpfPkg+".SpinLock"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".Timer"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".WithLock"] = apiEntry{sideEBPF, "with_lock"}
	apiTable[bpfPkg+".Timer.Init"] = apiEntry{sideEBPF, "timer_init"}
	apiTable[bpfPkg+".Timer.SetCallback"] = apiEntry{sideEBPF, "timer_set_callback"}
	apiTable[bpfPkg+".Timer.Start"] = apiEntry{sideEBPF, "timer_start"}
}

// tp_btf and CO-RE. TPArg is a generic eBPF side function (a kernel struct pointer argument of the tracepoint), Kernel the marker of a local kernel type.
func init() {
	apiTable[bpfPkg+".TPBTFContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".Kernel"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".TPArg"] = apiEntry{sideEBPF, "tp_arg"}
	apiTable[bpfPkg+".TPArgInt"] = apiEntry{sideEBPF, "tp_arg_int"}         // an integer argument of tp_btf
	apiTable[bpfPkg+".FentryArg"] = apiEntry{sideEBPF, "fentry_arg"}        // a kernel pointer argument of fentry
	apiTable[bpfPkg+".FentryArgInt"] = apiEntry{sideEBPF, "fentry_arg_int"} // an integer argument of fentry
}

// Sockets and cgroups. Field methods have op "ctx_field" (field and r / w are in ctxFieldOfMethod of sockcg.go, permission in the hook table).
func init() {
	methods := map[string][]string{
		"SocketFilterContext":     {"Len"},
		"CgroupSKBIngressContext": {"Len"},
		"CgroupSKBEgressContext":  {"Len"},
		"CgroupSockContext":       {"Family", "Type", "Protocol", "SrcIP4", "SrcPort", "SetMark"},
		"SockAddrContext":         {"Family", "Type", "Protocol", "UserIP4", "UserPort", "SetUserIP4", "SetUserPort"},
		"SockOpsContext":          {"Op", "Family", "RemotePort", "LocalPort", "SetReply"},
		"CgroupDeviceContext":     {"AccessType", "Major", "Minor"},   // cgroup_device
		"CgroupSysctlContext":     {"Write", "FilePos", "SetFilePos"}, // cgroup_sysctl
		// lwt_in / lwt_out / lwt_xmit
		"LWTInContext":   {"Len"},
		"LWTOutContext":  {"Len"},
		"LWTXmitContext": {"Len"},
		// lwt_seg6local
		"Seg6LocalContext": {"Len", "Mark", "SetMark", "Priority", "SetPriority", "Protocol", "Ifindex"},
		// sk_lookup and sk_reuseport
		"SkLookupContext":    {"Family", "Protocol", "LocalIP4", "LocalPort", "RemotePort"},
		"SkReuseportContext": {"Len", "EthProtocol", "IPProtocol", "BindInany", "Hash"},
		// cgroup_sockopt
		"CgroupSetsockoptContext": {"Level", "Optname", "Optlen", "SetOptlen"},
		"CgroupGetsockoptContext": {"Level", "Optname", "Optlen", "SetOptlen"},
	}
	for t, ms := range methods {
		apiTable[bpfPkg+"."+t] = apiEntry{sideBoth, ""}
		for _, m := range ms {
			apiTable[bpfPkg+"."+t+"."+m] = apiEntry{sideEBPF, "ctx_field"}
		}
	}
	apiTable[bpfPkg+".CgroupSysctlContext.SetNewValue"] = apiEntry{sideEBPF, "sysctl_set"} // ebpf.sysctl.set_new_value
	// lwt_in / lwt_out / lwt_xmit (packet window reads, verdict LWTAction)
	for _, c := range []string{"LWTInContext", "LWTOutContext", "LWTXmitContext"} {
		apiTable[bpfPkg+"."+c+".Check"] = apiEntry{sideEBPF, "packet_check"}
	}
	apiTable[bpfPkg+".LWTAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".LWTOK"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".LWTDrop"] = apiEntry{sideBoth, "verdict"}
	// lwt_seg6local (verdict Seg6Action — redirect is never emitted)
	apiTable[bpfPkg+".Seg6Action"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".Seg6OK"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".Seg6Drop"] = apiEntry{sideBoth, "verdict"}
	// netfilter (kfield reads of the state / skb kernel pointers, verdict NFAction)
	apiTable[bpfPkg+".NetfilterContext"] = apiEntry{sideBoth, ""}
	for name := range nfReads {
		apiTable[bpfPkg+".NetfilterContext."+name] = apiEntry{sideEBPF, "nf_read"}
	}
	apiTable[bpfPkg+".NFAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".NFDrop"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".NFAccept"] = apiEntry{sideBoth, "verdict"}
	// flow_dissector (packet windows and flow_keys reads / writes, verdict FlowAction)
	apiTable[bpfPkg+".FlowDissectorContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".FlowDissectorContext.Check"] = apiEntry{sideEBPF, "packet_check"}
	for name := range flowKeyFields {
		apiTable[bpfPkg+".FlowDissectorContext."+name] = apiEntry{sideEBPF, "flow_keys_load"}
		apiTable[bpfPkg+".FlowDissectorContext.Set"+name] = apiEntry{sideEBPF, "flow_keys_store"}
	}
	apiTable[bpfPkg+".FlowAction"] = apiEntry{sideBoth, ""}
	for _, n := range []string{"FlowOK", "FlowDrop", "FlowContinue"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideBoth, "verdict"}
	}
	apiTable[bpfPkg+".CgroupSetsockoptContext.Check"] = apiEntry{sideEBPF, "packet_check"} // the optval window
	apiTable[bpfPkg+".CgroupGetsockoptContext.Check"] = apiEntry{sideEBPF, "packet_check"}
	apiTable[bpfPkg+".CgroupSKBIngressContext.Check"] = apiEntry{sideEBPF, "packet_check"}
	apiTable[bpfPkg+".CgroupSKBEgressContext.Check"] = apiEntry{sideEBPF, "packet_check"}
	apiTable[bpfPkg+".CgroupAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".CgroupDeny"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".CgroupAllow"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".SocketFilterAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SocketDrop"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".SocketKeep"] = apiEntry{sideBoth, "verdict"}
}

// lsm and lsm.s. LSMDeny only in a return expression (a constant errno — lsmRet in lower), LSMHook is the type constraint of LSMArg / LSMArgInt.
func init() {
	apiTable[bpfPkg+".LSMContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".LSMSleepableContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".LSMCgroupContext"] = apiEntry{sideBoth, ""} // lsm_cgroup (the verdict is CgroupAction)
	apiTable[bpfPkg+".LSMHook"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".LSMRet"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".LSMAllow"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".LSMDeny"] = apiEntry{sideBoth, "lsm_deny"}
	apiTable[bpfPkg+".LSMArg"] = apiEntry{sideEBPF, "lsm_arg"}
	apiTable[bpfPkg+".LSMArgInt"] = apiEntry{sideEBPF, "lsm_arg_int"}
}

// User ring buffers. Drain is ebpf.user_ringbuf.drain (the callback is a named function — userringbuf.go).
func init() {
	apiTable[bpfPkg+".UserRingBuf"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".UserRingBuf.Drain"] = apiEntry{sideEBPF, "urb_drain"}
}

// syscall. SyscallRet is a computed i32 return value (IntRetExpr), SyscallLoad an integer read of ctx (ebpf.ctx.load).
func init() {
	apiTable[bpfPkg+".SyscallContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SyscallRet"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SyscallLoad"] = apiEntry{sideEBPF, "syscall_load"}
	// the three pointer-free cmds of bpf() (sys.bpf) and sys.close.
	apiTable[bpfPkg+".SysBpf"] = apiEntry{sideEBPF, "sys_bpf"}
	apiTable[bpfPkg+".SysClose"] = apiEntry{sideEBPF, "sys_close"}
	for _, n := range []string{"SysBpfCmd", "SysBpfMapCreate", "SysBpfMapGetFdByID", "SysBpfMapFreeze"} {
		apiTable[bpfPkg+"."+n] = apiEntry{sideBoth, ""}
	}
}

// struct_ops. TCPCongestionOps is a map declaration (Name only), StructOpsContext the program context.
func init() {
	p := bpfPkg + ".TCPCongestionOps"
	apiTable[p] = apiEntry{sideBoth, ""}
	for _, n := range []string{"Name", "GobpfTypes", "GobpfMapKind", "GobpfStructOps", "GobpfMaxEntries"} {
		apiTable[p+"."+n] = apiEntry{sideUser, ""}
	}
	apiTable[bpfPkg+".StructOpsContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".StructOpsArg"] = apiEntry{sideEBPF, "structops_arg"}        // a struct argument of a member (kptr_or_null)
	apiTable[bpfPkg+".StructOpsArgInt"] = apiEntry{sideEBPF, "structops_arg_int"} // an integer argument of a member
}

// ext. The result is the result type of the replaced function (ebpf.return), ExtArg an argument of the replaced function (ebpf.ext.arg).
func init() {
	apiTable[bpfPkg+".ExtContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".ExtArg"] = apiEntry{sideEBPF, "ext_arg"}
}

// fmod_ret. FmodRet is a computed i32 return value (intRetExpr in lower), FmodRetArgInt an integer argument of the function.
func init() {
	apiTable[bpfPkg+".FmodRetContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".FmodRet"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".FmodRetArgInt"] = apiEntry{sideEBPF, "fmod_ret_arg_int"}
}

// multi probes.
func init() {
	apiTable[bpfPkg+".MultiProbeContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".ProbeTargetIndex"] = apiEntry{sideEBPF, "probe_target_index"}
}

// ksyscall.
func init() {
	apiTable[bpfPkg+".KsyscallContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KsyscallArg"] = apiEntry{sideEBPF, "ksyscall_arg"}
}

// sockmap, sockhash and sk_skb. The eBPF side has only the terminal Redirect / RedirectIf; user space Sets entries.
func init() {
	for _, t := range []string{"SockMap", "SockHash"} {
		p := bpfPkg + "." + t
		apiTable[p] = apiEntry{sideBoth, ""}
		apiTable[p+".MaxEntries"] = apiEntry{sideUser, ""}
		apiTable[p+".Redirect"] = apiEntry{sideEBPF, "sk_redirect"}
		apiTable[p+".RedirectIf"] = apiEntry{sideEBPF, "sk_redirect_if"}
		apiTable[p+".MsgRedirect"] = apiEntry{sideEBPF, "msg_redirect"}      // sk_msg
		apiTable[p+".MsgRedirectIf"] = apiEntry{sideEBPF, "msg_redirect_if"} // sk_msg
		apiTable[p+".Insert"] = apiEntry{sideEBPF, "sock_insert"}            // sock.map_update of sock_ops
		apiTable[p+".Assign"] = apiEntry{sideEBPF, "sk_assign"}              // sk.assign of sk_lookup
		for _, n := range []string{"Set", "Remove", "GobpfTypes", "GobpfMapKind"} {
			apiTable[p+"."+n] = apiEntry{sideUser, ""}
		}
	}
	apiTable[bpfPkg+".SKSKBContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SKSKBContext.Len"] = apiEntry{sideEBPF, "ctx_field"}
	apiTable[bpfPkg+".SKSKBContext.LocalPort"] = apiEntry{sideEBPF, "ctx_field"}
	apiTable[bpfPkg+".SKAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SKDirection"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SKDrop"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".SKPass"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".SKEgress"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SKIngress"] = apiEntry{sideBoth, ""}
	// the sk_msg context and fields, and the flags of Insert.
	apiTable[bpfPkg+".SKMsgContext"] = apiEntry{sideBoth, ""}
	for _, m := range []string{"Size", "Family", "RemoteIP4", "LocalIP4", "RemotePort", "LocalPort"} {
		apiTable[bpfPkg+".SKMsgContext."+m] = apiEntry{sideEBPF, "ctx_field"}
	}
	apiTable[bpfPkg+".SockFlags"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SockAny"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SockNoExist"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SockExist"] = apiEntry{sideBoth, ""}
	// the flags of Assign.
	apiTable[bpfPkg+".SkAssignFlags"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SkAssignReplace"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SkAssignNoReuseport"] = apiEntry{sideBoth, ""}
}

// Ring buffer reservations. Reserve only in the init statement of an if (reserve.go), Submit / Discard are the consumes in the present arm.
func init() {
	apiTable[bpfPkg+".RingBuf.Reserve"] = apiEntry{sideEBPF, "ringbuf_reserve"}
	apiTable[bpfPkg+".RingBuf.Submit"] = apiEntry{sideEBPF, "ringbuf_submit"}
	apiTable[bpfPkg+".RingBuf.Discard"] = apiEntry{sideEBPF, "ringbuf_discard"}
}

// sched_act. There is no attach (test run only).
func init() {
	p := bpfPkg + ".TCActContext"
	apiTable[p] = apiEntry{sideBoth, ""}
	apiTable[p+".Check"] = apiEntry{sideEBPF, "packet_check"}
	apiTable[p+".Len"] = apiEntry{sideEBPF, "ctx_field"}
	apiTable[p+".SetMark"] = apiEntry{sideEBPF, "ctx_field"}
	apiTable[bpfPkg+".TCActAction"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".TCActOK"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".TCActShot"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".TCActPipe"] = apiEntry{sideBoth, "verdict"}
}

// usdt.
func init() {
	apiTable[bpfPkg+".USDTContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".USDTArg"] = apiEntry{sideEBPF, "usdt_arg"}
}

// perf_event.
func init() {
	apiTable[bpfPkg+".PerfEventContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".PerfEventContext.SamplePeriod"] = apiEntry{sideEBPF, "perf_sample_period"}
	// iter (seq_num and seq of bpf_iter_meta, seq.write)
	apiTable[bpfPkg+".IterContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".IterContext.SeqNum"] = apiEntry{sideEBPF, "iter_seq_num"}
	apiTable[bpfPkg+".IterContext.Seq"] = apiEntry{sideEBPF, "iter_seq"}
	apiTable[bpfPkg+".SeqFile"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".SeqFile.Write"] = apiEntry{sideEBPF, "seq_write"}
	// fsession (session ops)
	apiTable[bpfPkg+".FsessionContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".FsessionContext.IsReturn"] = apiEntry{sideEBPF, "session_is_return"}
	apiTable[bpfPkg+".FsessionContext.Cookie"] = apiEntry{sideEBPF, "session_cookie"}
	apiTable[bpfPkg+".FsessionContext.SetCookie"] = apiEntry{sideEBPF, "session_set_cookie"}
	// kprobe_session (the same session ops, the return value is a constant KprobeSessionRet)
	apiTable[bpfPkg+".KprobeSessionContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KprobeSessionContext.IsReturn"] = apiEntry{sideEBPF, "session_is_return"}
	apiTable[bpfPkg+".KprobeSessionContext.Cookie"] = apiEntry{sideEBPF, "session_cookie"}
	apiTable[bpfPkg+".KprobeSessionContext.SetCookie"] = apiEntry{sideEBPF, "session_set_cookie"}
	apiTable[bpfPkg+".KprobeSessionRet"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KprobeSessionRun"] = apiEntry{sideBoth, "verdict"}
	apiTable[bpfPkg+".KprobeSessionSkipReturn"] = apiEntry{sideBoth, "verdict"}
}

// tracepoint, raw_tp, kretprobe, uretprobe.
func init() {
	apiTable[bpfPkg+".TracepointContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".TracepointContext.Event"] = apiEntry{sideEBPF, "tp_event"} // only the shape ctx.Event().F
	apiTable[bpfPkg+".RawTPContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".RawTPArg"] = apiEntry{sideEBPF, "rawtp_arg"}
	// the writable buffer of raw_tp_writable (ebpf.tp.buffer.load / store — an i32 at offset 0)
	apiTable[bpfPkg+".RawTPWritableContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".RawTPWritableContext.Buffer"] = apiEntry{sideEBPF, "tpbuf_load"}
	apiTable[bpfPkg+".RawTPWritableContext.SetBuffer"] = apiEntry{sideEBPF, "tpbuf_store"}
	apiTable[bpfPkg+".RetInt"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KretprobeContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".KretprobeContext.Ret"] = apiEntry{sideEBPF, "retprobe_ret"}
	apiTable[bpfPkg+".UretprobeContext"] = apiEntry{sideBoth, ""}
	apiTable[bpfPkg+".UretprobeContext.Ret"] = apiEntry{sideEBPF, "retprobe_ret"}
}
