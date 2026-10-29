// Package gobpf is the user-space runtime that loads and attaches the eBPF side embedded in one Go program (the ELF built by the gobpf frontend)
// (the user-space side).
//
// The generated file (gobpf_gen.go) calls Register in init and registers the embedded ELF and the mapping between the user's declarations (map variables, program functions) and
// the ELF symbols. The user calls Load / AttachXDP and the user-space methods of the map variables (bpf.Array.Get and so on).
//
// The load contract is the same as bpf-mlir's ebpf-bindgen output (LoadObjects in v0.2.0's examples/go/xdp-counter/objects_gen.go)
// (pinned by tests):
//
//   - Load(caps) is the default entry and checks the requirements against caps. nil caps never skip the check; they are an error. A failure of the check itself is
//     *PrecheckError, a mismatch that stops the load (requirements.Unmet.BlocksLoad) is *TargetError, and neither loads the embedded program.
//     Unmet entries that did not stop it (Unknown) are returned after load
//   - A load without the check exists only under the name LoadUnchecked
//   - Both first run the checks that do not touch the kernel — the requirements are parsed once (bindrt.Parse), then the schema SHA-256 (*SchemaMismatchError),
//     the record layouts and the map declarations (bindrt.CheckMapDecls — both directions, *MapDeclError). Load runs these before the caps probe
//   - Tail call slots: the check bindrt.CheckTailSlots (*TailSlotError), which does not touch the kernel, runs at the same stage as above, and after load only the declared slots
//     are set in the prog_array. **LoadUnchecked skips only the kernel capability check (Precheck)** — the slot check and setting are the same as Load
package gobpf

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// Object is the embedded object the generated file registers.
type Object struct {
	ELF            []byte
	SchemaSHA256   string // SHA-256 of the schema file at generation (checked against the ELF's .ebpf_requirements)
	Maps           []Map
	Programs       []Program
	Records        []Record   // the record layout table (checked against the ELF's BTF before load)
	MapValues      []MapValue // maps whose value is a record, and that record
	RingBufRecords []MapValue // ring buffers and their event records (the BTF map definition has no value, so outside CheckMapValues; only V is checked)
	PerfRecords    []MapValue // perf_event_arrays and their payload records (the ELF map value is u32, so only V is checked)
	TailSlots      []TailSlot // prog_array slot declarations (bpf.TailSlot; Load checks them against the ELF's tailslot rows and sets them after load)
	Globals        []Global   // global variables (bpf.Config in .rodata, bpf.Global in .bss; Load runs CheckGlobals and sets .rodata)
}

// TailSlot is the declaration of one prog_array slot (written by the generated file — Pos is the position of the bpf.TailSlot call).
type TailSlot struct {
	Map     string
	Slot    uint32
	Program string
	Pos     string
}

// Map is the user's map variable (Var is a pointer to the variable) and the ELF's map symbol.
type Map struct {
	Symbol string
	Var    any
	Pos    string // position of the Go declaration (package-relative file:line:col — written by the generated file; check errors point to it)
}

// Record is a record layout the generated file registers (bpf-mlir go/layout's Record and the user's Go type).
// New returns a pointer to the zero value of the generated type gobpf_T (the same fields as the user's type T — it has Decode). Type is the user's type T.
type Record struct {
	Symbol string
	Size   uintptr
	Type   reflect.Type
	New    func() Decoder
}

// Decoder is the generated gobpf_T's Decode (reads by offset — the same shape as bpf-mlir's bindgen).
type Decoder = layout.Decoder

// MapValue is a map whose value is a record, and that record (layout.CheckMapValues checks it against the ELF's BTF .maps).
type MapValue = layout.MapValue

// Program is the user's program function and the ELF's program symbol.
type Program struct {
	Symbol string
	Kind   string // "xdp" / "sched_cls"
	Attach string // the tcx direction of sched_cls ("ingress" / "egress")
	Func   any
	// PerfMaps are the perf_event_arrays the program outputs to (AttachFentry confirms an open reader exists).
	PerfMaps []string
	// USDTSpec is the max_entries of a usdt program's compiler spec map `__ebpf_usdt_spec_<Symbol>` (the schema's max_points).
	// 0 means no spec map (a usdt program without USDTArg, or another kind).
	USDTSpec uint32
	// IterMap is the name of the map an iter program iterates over (directive `//gobpf:iter bpf_map_elem <map>`).
	IterMap string
	// ExtTarget is the name of the program an ext program replaces into (directive `//gobpf:ext <program> <function>`). Load uses this program of the same object
	// as the AttachTarget of the ext load (no other program is accepted).
	ExtTarget string
}

var (
	mu         sync.Mutex
	registered *Object
	loadedObjs *Objects
)

// Register is called from the generated file's init (the user does not call it). Only one per binary.
func Register(o Object) {
	mu.Lock()
	defer mu.Unlock()
	if registered != nil {
		panic("gobpf: Register called twice — one embedded object per binary")
	}
	cp := o
	registered = &cp
	for _, m := range o.Maps {
		binding.Declare(m.Var, m.Symbol)
	}
	for _, g := range o.Globals {
		binding.DeclareGlobal(g.Var, g.Symbol)
	}
}

// ErrNoObject means there is no embedded object (go generate was not run, or a build for an unsupported GOOS / GOARCH).
var ErrNoObject = errors.New("gobpf: no embedded eBPF object in this binary (run `go generate` — the generated file is built only for linux/amd64)")

// ErrAlreadyLoaded means Load was called twice (before Close).
var ErrAlreadyLoaded = errors.New("gobpf: the embedded object is already loaded (call Objects.Close before loading again)")

// TargetError is a requirement mismatch that stops the load (BlocksLoad of requirements.Unmet). No kernel object was created.
// An alias of bpf-mlir's go/bindrt type (bindrt holds the contract decisions in one place; its golden pins the messages and fields).
type TargetError = bindrt.TargetError

// PrecheckError is a failure of the default load entry's target check itself (a caps probe error, unreadable requirements, nil caps and so on).
// It stopped before the embedded program was loaded. The cause is reachable with Unwrap — an alias of the bindrt type.
type PrecheckError = bindrt.PrecheckError

// RequirementsError means the embedded ELF's requirements section cannot be read (an alias of the bindrt type since bpf-mlir v0.4.0).
type RequirementsError = bindrt.RequirementsError

// SchemaMismatchError means the SHA-256 of the schema that built the ELF differs from the generated file's (a build that did not rerun go generate — an alias of the bindrt type).
type SchemaMismatchError = bindrt.SchemaMismatchError

// MapDeclError is a mismatch between the Go map declarations and the ELF requirements' map rows (bindrt.CheckMapDecls — both directions; an alias of the bindrt type).
// The Problems' Field (missing_in_elf / undeclared / kind / key / value / max_entries) tells what differs.
type MapDeclError = bindrt.MapDeclError

// MapDeclProblem is one mismatch in a MapDeclError (an alias of the bindrt type).
type MapDeclProblem = bindrt.MapDeclProblem

// regenerateHint is gobpf's fix (the end of bindrt's error messages and of the messages gobpf wraps).
const regenerateHint = "run go generate again"

// The embedded ELF's requirements are parsed only once: the bindrt.Parse result is kept per registered object and ELF.
// The embedded ELF does not change within a process (tests register objects again — then it is parsed again).
var (
	parsedObj   *Object
	parsedELF   *byte
	parsedLen   int
	parsedReqs  *bindrt.Parsed
	parseCalled int // test hook: the number of bindrt.Parse calls
)

// parsedOf parses o's ELF requirements only once. If unreadable, *RequirementsError.
func parsedOf(o *Object) (*bindrt.Parsed, error) {
	mu.Lock()
	defer mu.Unlock()
	if parsedObj == o && parsedELF == unsafe.SliceData(o.ELF) && parsedLen == len(o.ELF) && parsedReqs != nil {
		return parsedReqs, nil
	}
	parseCalled++
	p, err := bindrt.Parse(o.ELF)
	if err != nil {
		return nil, err
	}
	parsedObj, parsedELF, parsedLen, parsedReqs = o, unsafe.SliceData(o.ELF), len(o.ELF), p
	return p, nil
}

// verifyEmbedded is the pre-load check that does not touch the kernel: from one parse, (1) the schema hash → (2) record layouts → (3) map declarations → (3') tail call slots.
// Load runs this before the caps probe ((4) Precheck) (stale generated files say "regenerate" first, even when capabilities are missing).
func verifyEmbedded(o *Object) (*bindrt.Parsed, error) {
	p, err := parsedOf(o)
	if err != nil {
		return nil, err
	}
	if err := p.CheckSchema(o.SchemaSHA256, regenerateHint); err != nil {
		return nil, err // *SchemaMismatchError (regenerateHint at the end of the message)
	}
	if err := checkLayout(o, p); err != nil {
		return nil, err
	}
	if err := checkTailSlots(o, p); err != nil {
		return nil, err
	}
	return p, nil
}

func current() (*Object, error) {
	mu.Lock()
	defer mu.Unlock()
	if registered == nil {
		return nil, ErrNoObject
	}
	return registered, nil
}

// CheckSchemaOf confirms that the schema SHA-256 in the ELF's .ebpf_requirements equals the value at generation (bindrt.CheckSchema — the fix hint is gobpf's procedure).
func CheckSchemaOf(elf []byte, want string) error {
	return bindrt.CheckSchema(elf, want, "run go generate again")
}

// LoadCollectionSpec parses the embedded ELF (without touching the kernel). A schema hash mismatch is refused before parsing.
// **The low-level path**: calling spec.LoadAndAssign and so on directly from here does not check the requirements — the caller runs CheckTarget first.
func LoadCollectionSpec() (*ebpf.CollectionSpec, error) {
	o, err := current()
	if err != nil {
		return nil, err
	}
	if _, err := verifyEmbedded(o); err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(o.ELF))
	if err != nil {
		return nil, err
	}
	if err := checkCPUMaps(spec); err != nil {
		return nil, err
	}
	return spec, nil
}

// checkCPUMaps checks that a cpumap's MaxEntries does not exceed the number of possible CPUs (/sys/devices/system/cpu/possible — readable without root).
// cilium v0.22 silently shrinks an exceeding cpumap MaxEntries to the possible count (fixupMapSpec in map.go) — never let it create a map that differs from the declaration.
func checkCPUMaps(spec *ebpf.CollectionSpec) error {
	for name, ms := range spec.Maps {
		if ms.Type != ebpf.CPUMap {
			continue
		}
		n, err := ebpf.PossibleCPU()
		if err != nil {
			return fmt.Errorf("gobpf: cpumap %s: cannot read the possible CPUs: %w", name, err)
		}
		if ms.MaxEntries > uint32(n) {
			return fmt.Errorf("gobpf: cpumap %s: MaxEntries %d exceeds the %d possible CPUs of this machine (/sys/devices/system/cpu/possible) — cilium/ebpf would silently shrink the map to %d; declare MaxEntries ≤ %d", name, ms.MaxEntries, n, n, n)
		}
	}
	return nil
}

// CheckTarget checks the embedded ELF's requirements against caps and returns every Unmet. It creates no kernel object. nil caps are an error.
// The verdict is bindrt.CheckTarget. **gobpf's wrapper decides the order**: nil caps are checked before a missing embedded object (ErrNoObject).
func CheckTarget(caps requirements.Capabilities) ([]requirements.Unmet, error) {
	if caps == nil {
		return bindrt.CheckTarget(nil, caps) // the nil caps error (the ELF is not read)
	}
	o, err := current()
	if err != nil {
		return nil, err
	}
	p, err := parsedOf(o)
	if err != nil {
		return nil, err
	}
	return p.CheckTarget(withExtTargets(o, withGobpfLoader(o, caps))) // the same loader declaration as Load, and the ext check
}

// Objects are the loaded programs and maps.
type Objects struct {
	coll    *ebpf.Collection
	obj     *Object
	closed  bool
	uprobes map[string]*uprobeTarget // targets of the uprobe programs (Load's WithUprobeTarget)
}

// Load is the default load entry: it checks the requirements against caps (precheck), and on a mismatch that stops the load returns
// *TargetError without creating any kernel object. Otherwise it loads and returns the Unmet entries that did not stop it (Unknown — the caller records them).
func Load(caps requirements.Capabilities, opts ...LoadOption) (*Objects, []requirements.Unmet, error) {
	if _, err := current(); err != nil {
		return nil, nil, err
	}
	mu.Lock()
	already := loadedObjs != nil
	mu.Unlock()
	if already {
		return nil, nil, ErrAlreadyLoaded // before running any probe
	}
	obj, _ := current()
	// The checks that do not touch the kernel ((1) to (3)) run before the caps probe ((4)) (stale generated files are named first, even when capabilities are missing).
	p, err := verifyEmbedded(obj)
	if err != nil {
		return nil, nil, err
	}
	if err := configsSet(obj); err != nil {
		return nil, nil, err // a missing user value (before the caps probe)
	}
	var cfg loadConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	wantSHA := map[string]string{}
	for _, a := range p.Requirements().Attaches {
		wantSHA[a.Program] = a.BinarySHA256
	}
	// uprobe targets: open the fd, check sha256, symbol, calling convention and arguments, and add the fd to caps (Precheck's gate sees the same fd).
	caps, targets, err := prepareUprobes(obj, caps, cfg, wantSHA)
	if err != nil {
		return nil, nil, err
	}
	closeTargets := func() {
		for _, t := range targets {
			t.f.Close()
		}
	}
	caps = withGobpfLoader(obj, caps) // the loader declaration for an object with ksyscall programs
	caps = withExtTargets(obj, caps)  // the check of ext targets (programs of the same object)
	rest, err := p.Precheck(caps)     // nil caps are also *PrecheckError (the check is never skipped)
	if err != nil {
		closeTargets()
		return nil, nil, withHint(err) // only adds a likely cause — the type stays reachable with errors.As
	}
	o, err := LoadUnchecked(nil)
	if err != nil {
		closeTargets()
		return nil, nil, err
	}
	o.uprobes = targets
	return o, rest, nil
}

// LoadUnchecked loads the embedded ELF **without checking the requirements**. The default checked entry is Load.
// **Unchecked skips only the kernel capability check (Precheck)** — the structural checks that do not touch the kernel (schema hash, layout, map declarations, tail call slots)
// run as in Load, and the declared tail call slots are set the same way.
func LoadUnchecked(opts *ebpf.CollectionOptions) (*Objects, error) {
	mu.Lock()
	if loadedObjs != nil {
		mu.Unlock()
		return nil, ErrAlreadyLoaded
	}
	mu.Unlock()
	spec, err := LoadCollectionSpec()
	if err != nil {
		return nil, fmt.Errorf("the embedded ELF was rejected before load (schema, layout, map declaration or tail-call slot check, or parse): %w", err)
	}
	if err := setRodata(current0(), spec); err != nil {
		return nil, err
	}
	stackNote, err := checkStackDepth(current0()) // before creating the maps
	if err != nil {
		return nil, err
	}
	second, err := splitExt(current0(), spec) // ext programs load in a second stage (after their target programs)
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, derefOpts(opts))
	if err != nil {
		if stackNote != "" && errors.Is(err, unix.EINVAL) {
			err = fmt.Errorf("%w (%s)", err, stackNote)
		}
		return nil, withHint(err) // such as the CAP_PERFMON hint for a !root refusal of a variable offset
	}
	if second != nil {
		if err := loadExt(current0(), coll, second, derefOpts(opts)); err != nil {
			coll.Close()
			return nil, withHint(err)
		}
	}
	o, _ := current()
	if err := setTailSlots(o, coll); err != nil {
		coll.Close() // before the map variables are bound — Load can be called again
		return nil, err
	}
	if err := bindGlobals(o, coll); err != nil {
		coll.Close()
		return nil, err
	}
	for _, m := range o.Maps {
		km, ok := coll.Maps[m.Symbol]
		if !ok {
			coll.Close()
			return nil, fmt.Errorf("gobpf: the embedded ELF has no map %q (regenerate with go generate)", m.Symbol)
		}
		if err := binding.Bind(m.Var, km); err != nil {
			coll.Close()
			return nil, err
		}
		if ms := spec.Maps[m.Symbol]; ms != nil && ms.InnerMap != nil {
			binding.BindInner(m.Var, ms.InnerMap) // the template for map-in-map NewInner
		}
	}
	objs := &Objects{coll: coll, obj: o}
	mu.Lock()
	loadedObjs = objs
	mu.Unlock()
	return objs, nil
}

func derefOpts(o *ebpf.CollectionOptions) ebpf.CollectionOptions {
	if o == nil {
		return ebpf.CollectionOptions{}
	}
	return *o
}

// Close closes the loaded programs and maps and puts the map variables in the after-Close state.
func (o *Objects) Close() error {
	mu.Lock()
	defer mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	closeReaders() // ring buffer readers before the maps
	for _, t := range o.uprobes {
		t.f.Close()
	}
	for _, m := range o.obj.Maps {
		binding.Unbind(m.Var)
	}
	for _, g := range o.obj.Globals {
		binding.UnbindGlobal(g.Var)
	}
	if loadedObjs == o {
		loadedObjs = nil
	}
	o.coll.Close()
	return nil
}

// Program returns the loaded program for a program function value (such as CountPackets).
func (o *Objects) Program(fn any) (*ebpf.Program, error) {
	if o.closed {
		return nil, errors.New("gobpf: Objects is closed")
	}
	sym, err := o.symbolOf(fn)
	if err != nil {
		return nil, err
	}
	p, ok := o.coll.Programs[sym]
	if !ok {
		return nil, fmt.Errorf("gobpf: the embedded ELF has no program %q", sym)
	}
	return p, nil
}

func (o *Objects) symbolOf(fn any) (string, error) {
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		return "", fmt.Errorf("gobpf: %T is not a program function", fn)
	}
	for _, p := range o.obj.Programs {
		if reflect.ValueOf(p.Func).Pointer() == v.Pointer() {
			return p.Symbol, nil
		}
	}
	return "", fmt.Errorf("gobpf: the function is not a program of the embedded object (is it a func(*bpf.XDPContext) bpf.XDPAction in the generated package?)")
}

// AttachXDP attaches an xdp program (a function value) to the interface ifindex.
func AttachXDP(o *Objects, fn any, ifindex int) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	if e := o.entryOf(fn); e != nil && isTracingKind(e.Kind) {
		return nil, fmt.Errorf("gobpf.AttachXDP: program %s is a %s program (%s) — attach it with gobpf.Attach%s", e.Symbol, e.Kind, e.Attach, tracingAttachName(e.Kind))
	}
	if e := o.entryOf(fn); e != nil && e.Kind != "xdp" {
		return nil, fmt.Errorf("gobpf.AttachXDP: program %s is a %s program (tcx %s) — attach it with gobpf.AttachTCX", e.Symbol, e.Kind, e.Attach)
	}
	return link.AttachXDP(link.XDPOptions{Program: p, Interface: ifindex})
}

// AttachTCX attaches a sched_cls program (a function value) to the tcx of the interface ifindex. **The direction follows from the program's context
// type** (*bpf.TCIngressContext is ingress, *bpf.TCEgressContext is egress) — it is not chosen at attach time. An xdp program is a named error.
func AttachTCX(o *Objects, fn any, ifindex int) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e != nil && isTracingKind(e.Kind) {
		return nil, fmt.Errorf("gobpf.AttachTCX: program %s is a %s program (%s) — attach it with gobpf.Attach%s", e.Symbol, e.Kind, e.Attach, tracingAttachName(e.Kind))
	}
	if e == nil || e.Kind != "sched_cls" {
		kind := "unknown"
		if e != nil {
			kind = e.Kind
		}
		return nil, fmt.Errorf("gobpf.AttachTCX: the program is a %s program — attach an xdp program with gobpf.AttachXDP", kind)
	}
	at := ebpf.AttachTCXIngress
	switch e.Attach {
	case "ingress":
	case "egress":
		at = ebpf.AttachTCXEgress
	default:
		return nil, fmt.Errorf("gobpf.AttachTCX: program %s has an unknown tcx direction %q (regenerate with go generate)", e.Symbol, e.Attach)
	}
	return link.AttachTCX(link.TCXOptions{Program: p, Attach: at, Interface: ifindex})
}

// AttachFentry attaches a fentry program (a function value) to the kernel function in its directive `//gobpf:fentry <fn>` (cilium's
// link.AttachTracing; cilium resolves the attach target from the ELF section `fentry/<fn>` with the kernel's BTF). An xdp / sched_cls program is a named error.
// A non-root loader needs CAP_BPF + CAP_PERFMON (docs/nonroot.md).
func AttachFentry(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	if err := wantKind(o.entryOf(fn), "fentry", "gobpf.AttachFentry"); err != nil {
		return nil, err
	}
	if err := requirePerfReaders(o.entryOf(fn), "gobpf.AttachFentry"); err != nil {
		return nil, err // the reader comes before attaching
	}
	return link.AttachTracing(link.TracingOptions{Program: p})
}

// AttachFexit attaches a fexit program (a function value) to the kernel function in its directive `//gobpf:fexit <fn> nargs=<N>` (cilium's
// link.AttachTracing). The pre-load check (retsig) has already checked the signature (nargs and FexitContext's R) against the kernel — pass only programs loaded by Load
// (the signature of a LoadUnchecked program is not checked). An xdp / sched_cls / fentry program is a named error.
func AttachFexit(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	if err := wantKind(o.entryOf(fn), "fexit", "gobpf.AttachFexit"); err != nil {
		return nil, err
	}
	return link.AttachTracing(link.TracingOptions{Program: p})
}

// tracingAttachName is the second half of the attach function name for a tracing kind (fentry → Fentry).
func tracingAttachName(kind string) string {
	return map[string]string{"fentry": "Fentry", "fexit": "Fexit", "kprobe": "Kprobe", "uprobe": "Uprobe", "tp_btf": "TPBTF",
		"tracepoint": "Tracepoint", "raw_tp": "RawTP", "kretprobe": "Kretprobe", "uretprobe": "Uretprobe",
		"lsm": "LSM", "lsm_s": "LSM",
		"lsm_cgroup":   "Cgroup",
		"fsession":     "Fsession",
		"fmod_ret":     "FmodRet",
		"iter":         "Iter",
		"ksyscall":     "Ksyscall",
		"kprobe_multi": "KprobeMulti", "kretprobe_multi": "KprobeMulti",
		"uprobe_multi": "UprobeMulti", "uretprobe_multi": "UprobeMulti",
		"usdt":   "USDT",
		"sk_skb": "Sockmap", "sk_msg": "Sockmap",

		"raw_tp_writable": "RawTPWritable",
		"kprobe_session":  "KprobeSession",
		"ext":             "Ext"}[kind]
}

// wantKind returns, when the program's kind is not want, an error naming the right attach function.
func wantKind(e *Program, want, fn string) error {
	if e != nil && e.Kind == want {
		return nil
	}
	kind, with := "unknown", "gobpf.AttachXDP"
	if e != nil {
		kind = e.Kind
		switch e.Kind {
		case "sched_cls":
			with = "gobpf.AttachTCX"
		case "cgroup_skb", "cgroup_sock", "cgroup_sock_addr", "sock_ops":
			with = "gobpf.AttachCgroup"
		case "socket_filter":
			with = "gobpf.AttachSocketFilter"
		case "sk_lookup", "flow_dissector":
			with = "gobpf.AttachNetNs"
		case "sk_reuseport":
			with = "gobpf.AttachReuseport"
		case "netfilter":
			with = "gobpf.AttachNetfilter"
		case "lwt_in", "lwt_out", "lwt_xmit":
			with = "gobpf.AttachLWTRoute"
		case "lwt_seg6local":
			with = "gobpf.AttachSeg6Local"
		case "perf_event":
			with = "gobpf.AttachPerfEvent"
		default:
			if isTracingKind(e.Kind) {
				with = "gobpf.Attach" + tracingAttachName(e.Kind)
			}
		}
	}
	return fmt.Errorf("%s: the program is a %s program — attach it with %s", fn, kind, with)
}

// entryOf returns the registration row of a function value (nil if none).
func (o *Objects) entryOf(fn any) *Program {
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		return nil
	}
	for i := range o.obj.Programs {
		if reflect.ValueOf(o.obj.Programs[i].Func).Pointer() == v.Pointer() {
			return &o.obj.Programs[i]
		}
	}
	return nil
}

// CheckLayoutOf checks o's record layouts and map declarations against o's ELF (the same as CheckLayout in bpf-mlir's bindgen):
//
//  1. The kind, K, V and MaxEntries of every registered map variable and the record member shapes (name, offset, type) match the ELF requirements' map rows and BTF,
//     and every map in the ELF is registered — bindrt.CheckMapDecls (both directions, plus Records). It stops, before any kernel object is created, a build
//     whose Go declarations changed after generation without rerunning go generate
//  2. layout.CheckDecode — the generated Decode reads at the BTF offsets (member shapes are checked by 1.)
//  3. layout.CheckMapValues — the value of each map in the BTF .maps points to that record's struct
//
// It does not touch the kernel. A mismatch is a *MapDeclError (reachable with errors.As). LoadCollectionSpec and Load call it after the schema hash check (one parse).
func CheckLayoutOf(o *Object) error {
	p, err := parsedOf(o)
	if err != nil {
		return err
	}
	return checkLayout(o, p)
}

func checkLayout(o *Object, p *bindrt.Parsed) error {
	recs := make([]layout.Record, 0, len(o.Records))
	byType := map[reflect.Type]string{}
	for _, r := range o.Records {
		recs = append(recs, layout.Record{Symbol: r.Symbol, Size: r.Size, New: r.New})
		byType[r.Type] = r.Symbol
	}
	// (3) Turn the Go declarations into bindrt MapDecls (schema spellings u32 / i64 / record:S / -) and check them against the ELF requirements' map rows in both directions.
	// Declarations that cannot be spelled (not a shared type, a struct with no generated record) and the consistency of the generated table (a map with a record V has a row in MapValues / RingBufRecords) are
	// gobpf's checks outside bindrt — they stop before the MapDecls are built.
	valueRecord := map[string]string{}
	for _, mv := range o.MapValues {
		valueRecord[mv.Map] = mv.Record
	}
	for _, rr := range o.RingBufRecords {
		valueRecord[rr.Map] = rr.Record
	}
	perfRecord := map[string]string{}
	for _, pr := range o.PerfRecords {
		perfRecord[pr.Map] = pr.Record
	}
	spell := func(t reflect.Type) (string, bool) {
		if t == nil {
			return "-", true
		}
		return memberSpelling(t, byType) // integers, records, arrays (the stack_trace value [D]u64)
	}
	rows := map[string]requirements.Map{}
	for _, r := range p.Requirements().Maps {
		rows[r.Symbol] = r
	}
	var problems []string
	decls := make([]bindrt.MapDecl, 0, len(o.Maps))
	for _, m := range o.Maps {
		k, v, maxE, ok := mapTypes(m.Var)
		kd, hasKind := m.Var.(interface{ GobpfMapKind() string })
		if !ok || !hasKind {
			problems = append(problems, fmt.Sprintf("map %s: %T is not a map declaration", m.Symbol, m.Var))
			continue
		}
		// flags are explicit for every map (since bpf-mlir v0.17.0 omitted flags mean "flags 0": never rely on omission). A type without the marker method GobpfMapFlags is 0.
		flags := uint64(0)
		if mf, has := m.Var.(interface{ GobpfMapFlags() uint64 }); has {
			flags = mf.GobpfMapFlags()
		}
		d := bindrt.MapDecl{Name: m.Symbol, Kind: kd.GobpfMapKind(), MaxEntries: maxE, Flags: &flags}
		row, inELF := rows[m.Symbol]
		if !inELF || row.MapType != d.Kind {
			decls = append(decls, d) // bindrt names a map missing from the ELF or of a different kind (with a different kind K / V are not compared — nor spelled)
			continue
		}
		for _, side := range []struct {
			what string
			t    reflect.Type
			dst  *string
			elf  string
		}{{"key", k, &d.Key, row.Key}, {"value", v, &d.Value, row.Value}} {
			got, known := spell(side.t)
			switch {
			case !known && side.t.Kind() == reflect.Struct:
				problems = append(problems, fmt.Sprintf("map %s: the Go %s type %s has no generated record, but the embedded ELF holds %s", m.Symbol, side.what, side.t, side.elf))
			case !known:
				problems = append(problems, fmt.Sprintf("map %s: the Go %s type %s is not a shared type, but the embedded ELF holds %s", m.Symbol, side.what, side.t, side.elf))
			}
			*side.dst = got
		}
		if gi, isOuter := m.Var.(interface {
			GobpfInner() (kind string, key, value reflect.Type, maxEntries uint32)
		}); isOuter {
			// The inner template of a map-in-map — bindrt checks it against the ELF requirements' innermap row (format version 12).
			ik, ikt, ivt, ime := gi.GobpfInner()
			iks, _ := spell(ikt)
			ivs, _ := spell(ivt)
			d.Inner = &bindrt.InnerDecl{Kind: ik, Key: iks, Value: ivs, MaxEntries: uint64(ime)}
		}
		if sym, isRec := byType[v]; isRec && valueRecord[m.Symbol] != sym {
			problems = append(problems, fmt.Sprintf("map %s: the Go value type %s is a record, but the generated binding has no record for this map", m.Symbol, v))
		}
		if pe, isPerf := m.Var.(interface{ GobpfEvent() reflect.Type }); isPerf {
			// The perf_event_array payload: the ELF map row is u32 / u32 — V is checked against the record in the generated table's PerfRecords.
			if sym, isRec := byType[pe.GobpfEvent()]; !isRec || perfRecord[m.Symbol] != sym {
				problems = append(problems, fmt.Sprintf("map %s: the Go event type %s is not the generated perf record of this map (%q)", m.Symbol, pe.GobpfEvent(), perfRecord[m.Symbol]))
			}
		}
		decls = append(decls, d)
	}
	// The compiler's spec map of a usdt program (`__ebpf_usdt_spec_<program>` — not a user map; the shape from bpf-mlir's requirements_format.md:
	// array, u32, record:ebpf_usdt_spec, max_entries is the schema's max_points). It is declared from the generated table to keep the check in both directions.
	for _, pr := range o.Programs {
		if pr.Kind != "usdt" || pr.USDTSpec == 0 {
			continue
		}
		zero := uint64(0)
		decls = append(decls, bindrt.MapDecl{Name: requirements.USDTSpecMapPrefix + pr.Symbol, Kind: "array", Key: "u32", Value: "record:ebpf_usdt_spec", MaxEntries: uint64(pr.USDTSpec), Flags: &zero})
	}
	if len(problems) > 0 {
		return fmt.Errorf("gobpf: the map declarations cannot be checked against the embedded ELF (%s):\n  %s", regenerateHint, strings.Join(problems, "\n  "))
	}
	// The record member table: Go type → table is gobpf (reflect — schema tag names, Go offsets, spellings), table ↔ ELF BTF is
	// bindrt's Records (since bpf-mlir v0.7.0 — the same single check as the map declarations; a mismatch is a *MapDeclError with Field record / record_missing).
	recDecls := map[string]bindrt.RecordDecl{}
	for _, r := range o.Records {
		d, err := recordDecl(r, byType)
		if err != nil {
			return fmt.Errorf("gobpf: record %s: %w (%s)", r.Symbol, err, regenerateHint)
		}
		recDecls[r.Symbol] = d
	}
	gdecls, err := globalDecls(o)
	if err != nil {
		return err
	}
	if err := p.CheckMapDecls(decls, bindrt.MapDeclOptions{Records: recDecls, Globals: gdecls}); err != nil {
		if onlyGlobalProblems(err) { // global-only mismatches keep the globals message prefix (the type is *MapDeclError)
			return fmt.Errorf("gobpf: the global variables do not match the embedded ELF (%s): %w", regenerateHint, err)
		}
		return fmt.Errorf("gobpf: %s%s: %w", regenerateHint, goDeclsOf(o, err), err) // *MapDeclError — tell apart by Problems
	}
	// go/layout: whether the generated Decode reads at the BTF offsets (layout.CheckDecode — since bpf-mlir v0.10.0 it does not look at member shapes), and whether each BTF .maps map's
	// value points to a record (CheckMapValues). Member shapes are checked by bindrt's Records above — shapes are checked in one place (earlier there was no Decode-only entry and
	// layout.Check also checked shapes; the duplicate was removed).
	if len(recs) > 0 {
		if err := layout.CheckDecode(o.ELF, recs); err != nil {
			return fmt.Errorf("gobpf: the generated Decode of a record does not read the embedded ELF's layout (%s): %w", regenerateHint, err)
		}
		if err := layout.CheckMapValues(o.ELF, o.MapValues); err != nil {
			return fmt.Errorf("gobpf: the map values do not match the embedded ELF (%s): %w", regenerateHint, err)
		}
	}
	return nil
}

// recordDecl builds bindrt's member table from a record's Go type (schema tag names, Go offsets, spellings — explicit `_` padding is not a member).
func recordDecl(r Record, byType map[reflect.Type]string) (bindrt.RecordDecl, error) {
	t := r.Type
	if t == nil || t.Kind() != reflect.Struct {
		return bindrt.RecordDecl{}, fmt.Errorf("the Go type %v is not a struct", t)
	}
	d := bindrt.RecordDecl{Size: uint32(r.Size)}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("schema")
		if name == "" {
			continue
		}
		ty, ok := memberSpelling(f.Type, byType)
		if !ok {
			return bindrt.RecordDecl{}, fmt.Errorf("field %s has type %v, which is not a shared type", f.Name, f.Type)
		}
		d.Members = append(d.Members, bindrt.RecordMember{Name: name, Offset: uint32(f.Offset), Type: ty})
	}
	return d, nil
}

// memberSpelling is the spelling of a member type (bpf-mlir's specification — u8…i64, [N]T, record:<T>).
func memberSpelling(t reflect.Type, byType map[reflect.Type]string) (string, bool) {
	if t == reflect.TypeFor[bpf.StackBuildIDEntry]() {
		// A build-id stack element (bpf-mlir's map row spelling [D]stack_build_id). StackBuildIDEntry is a [32]byte array type, so
		// check it before the Kind switch (in the struct case, the array case would take it first and spell it [32]u8).
		return "stack_build_id", true
	}
	switch t.Kind() {
	case reflect.Array:
		elem, ok := memberSpelling(t.Elem(), byType)
		return fmt.Sprintf("[%d]%s", t.Len(), elem), ok
	case reflect.Struct:
		switch t {
		case reflect.TypeFor[bpf.SpinLock]():
			return "bpf_spin_lock", true // bindrt's spelling
		case reflect.TypeFor[bpf.Timer]():
			return "bpf_timer", true
		}
		sym, ok := byType[t]
		return "record:" + sym, ok
	}
	s, ok := intSpelling[t.Kind()]
	return s, ok
}

// intSpelling is the schema spelling of a reflect integer Kind (the same as the requirements' map rows).
var intSpelling = map[reflect.Kind]string{
	reflect.Uint8: "u8", reflect.Uint16: "u16", reflect.Uint32: "u32", reflect.Uint64: "u64",
	reflect.Int8: "i8", reflect.Int16: "i16", reflect.Int32: "i32", reflect.Int64: "i64",
}

// mapTypes reads a map variable's K (nil if none), V and MaxEntries — K / V from the bpf map type's marker method GobpfTypes (no longer
// relying on "the shape of the Get method" or "a `_ [0]V` field"), MaxEntries from the declaration's field.
func mapTypes(v any) (k, val reflect.Type, maxEntries uint64, ok bool) {
	m, isMap := v.(interface {
		GobpfTypes() (key, value reflect.Type)
	})
	if !isMap {
		return nil, nil, 0, false
	}
	if pm, isPerf := v.(interface{ GobpfMaxEntries() uint32 }); isPerf {
		k, val = m.GobpfTypes()
		return k, val, uint64(pm.GobpfMaxEntries()), true // perf_event_array has no MaxEntries field (0)
	}
	me := reflect.ValueOf(v).Elem().FieldByName("MaxEntries")
	if !me.IsValid() || me.Kind() != reflect.Uint32 {
		return nil, nil, 0, false
	}
	k, val = m.GobpfTypes()
	return k, val, me.Uint(), true
}

// DecodeLE reads the little-endian integer at the start of b into *dst (the width is *dst's type — used by the generated Decode; the user does not call it).
func DecodeLE[T ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~int8 | ~int16 | ~int32 | ~int64](dst *T, b []byte) {
	var u uint64
	for i := int(unsafe.Sizeof(*dst)) - 1; i >= 0; i-- {
		u = u<<8 | uint64(b[i])
	}
	*dst = T(u)
}

// ShortRecordError is the generated Decode's error for a short input.
func ShortRecordError(symbol string, got, want int) error {
	return fmt.Errorf("gobpf: record %s: %d bytes, need at least %d", symbol, got, want)
}

// goDeclsOf renders the Go declarations (position and type) of the maps in a *MapDeclError (bindrt's message has only schema spellings, so
// the Go declaration the user must fix is hard to find). The verdict and type do not change — it only adds text. A map in the ELF but undeclared has no Go declaration.
func goDeclsOf(o *Object, err error) string {
	var me *MapDeclError
	if !errors.As(err, &me) {
		return ""
	}
	byName := map[string]Map{}
	for _, m := range o.Maps {
		byName[m.Symbol] = m
	}
	var parts []string
	seen := map[string]bool{}
	for _, pr := range me.Problems {
		m, ok := byName[pr.Map]
		if !ok || seen[pr.Map] {
			continue
		}
		seen[pr.Map] = true
		at := ""
		if m.Pos != "" {
			at = " at " + m.Pos
		}
		parts = append(parts, fmt.Sprintf("var %s %s%s", pr.Map, goTypeName(m.Var), at))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (Go declaration: " + strings.Join(parts, "; ") + ")"
}

// goTypeName is the short name of a map variable's type (without the package path — such as bpf.Array[uint32,uint32]).
func goTypeName(v any) string {
	return pkgPath.ReplaceAllString(strings.TrimPrefix(fmt.Sprintf("%T", v), "*"), "")
}

var pkgPath = regexp.MustCompile(`[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)+/`)
