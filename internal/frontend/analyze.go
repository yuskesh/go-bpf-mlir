// Package frontend collects the eBPF side of one Go package and builds the .mlir of bpf-mlir's ebpf dialect and the schema JSON.
//
// Flow: read the package with build tag gobpf_frontend (excluding generated files) → collect map declarations and programs (roots by context type) →
// decide domains by reachability from the roots → check API misuse on both sides → lower the eBPF side to ① ops.
// Only shapes in the table (table.go) and the lowering switch are accepted; anything else stops with a positioned Diagnostic.
package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"golang.org/x/tools/go/packages"
)

// BuildTag is the build tag the frontend uses when reading the package. Generated files carry `//go:build !gobpf_frontend`.
const BuildTag = "gobpf_frontend"

// ReservedPrefix is the identifier prefix only generated files use.
const ReservedPrefix = "gobpf_"

// MapDecl is a map from the shared declarations.
// BpfMap is a map declaration. It is the kernel ↔ user-space ABI contract; key / value are SharedABI.
type BpfMap struct {
	Symbol     string // the Go variable name as is
	Kind       string // the schema kind ("array")
	Key, Value SharedABI
	MaxEntries uint64
	Flags      uint64          // 0 except lpm_trie's BPF_F_NO_PREALLOC (1)
	Slots      []*TailSlotDecl // prog_array slot declarations (bpf.TailSlot — index order)
	Event      *SharedABI      // the perf_event_array payload record (the schema map's record; Value is u32)
	InnerTpl   *BpfMap         // the inner template of a map-in-map (the schema's inner; not a map in the ELF .maps — not added to a.maps)
	StructOps  *StructOpsDecl  // the struct_ops map's type, name, members and programs (the schema's struct_ops)
	maxPos     token.Pos       // position of the MaxEntries value (for diagnostics)
	Pos        token.Position
	obj        *types.Var
}

// ABIKind is the kind of a shared type (a kind tag, replacing an embedded IntType so a record SharedABI cannot touch integer fields and misread zero values).
type ABIKind int

const (
	ABIInt ABIKind = iota + 1
	ABIRecord
	ABIArray
	ABISpinLock     // a bpf.SpinLock field (struct bpf_spin_lock — 4 bytes)
	ABITimer        // a bpf.Timer field (struct bpf_timer — 16 bytes)
	ABIStackBuildID // a build id stack element (struct bpf_stack_build_id — 32 bytes)
)

// SharedABI is one definition of a type shared by both sides. Of the per-kind fields, only the one Kind names is non-nil.
// Size / Align are the schema values. GoType is the declared Go type.
type SharedABI struct {
	Kind   ABIKind
	GoType types.Type
	Size   uint64
	Align  uint64
	Int    *IntType   // Kind == ABIInt
	Record *RecordABI // Kind == ABIRecord
	Array  *ArrayABI  // Kind == ABIArray
}

// RecordABI is the layout of a record (a Go struct) — Symbol is the Go type name (the schema record, the BTF struct).
type RecordABI struct {
	Symbol string
	GoExpr string // the Go type expression in generated files ("" means Symbol — a user type; keys owned by bpf are like "bpf.LPMKey4")
	Fields []FieldABI
	// Special is the lock or timer field (nil if none; at most one per record). DecodeType is the type expression of the generated gobpf_T (for a record with Special,
	// a struct with the lock / timer as an untouchable blank hole — the opaque shape of bpf-mlir's go/layout; "" if none, the same as GoType).
	Special    *FieldABI
	DecodeType string
	Pos        token.Position // the type declaration position (for generated files' provenance comments — not in the schema)
	// Depth is the nesting depth (1 for a flat record, 1 + the nested depth with a nested record field — the limit on field path components).
	Depth int
}

// PosString returns the position of the declaration.
func (r *RecordABI) PosString() string { return posString(r.Pos) }

// GoType returns the Go type expression for generated files.
func (r *RecordABI) GoType() string {
	if r.GoExpr != "" {
		return r.GoExpr
	}
	return r.Symbol
}

// FieldABI is a named record field (explicit padding `_ [N]byte` is excluded — a schema hole). Name is the `schema:"…"` tag.
type FieldABI struct {
	Name, GoName string
	Offset       uint64
	Type         SharedABI
}

// ArrayABI is a fixed-size array.
type ArrayABI struct {
	Count uint64
	Elem  SharedABI
}

func sharedABIOfInt(t types.Type, it IntType) SharedABI {
	cp := it
	return SharedABI{Kind: ABIInt, GoType: t, Size: uint64(it.Bits / 8), Align: uint64(it.Bits / 8), Int: &cp}
}

// intType returns the IntType of an integer SharedABI (false if not an integer — places that accept only integers check this and stop with a named error).
func (s SharedABI) intType() (IntType, bool) {
	if s.Kind != ABIInt || s.Int == nil {
		return IntType{}, false
	}
	return *s.Int, true
}

// mlir returns the ebpf dialect type text (iN for integers, !ebpf.record<"S", N> for records).
func (s SharedABI) mlir() string {
	switch s.Kind {
	case ABIInt:
		return s.Int.mlir()
	case ABIRecord:
		return fmt.Sprintf("!ebpf.record<%q, %d>", s.Record.Symbol, s.Size)
	}
	return fmt.Sprintf("<unsupported shared ABI kind %d>", s.Kind)
}

// IntType is a schema integer type.
type IntType struct {
	Bits   int
	Signed bool
}

func (t IntType) mlir() string { return fmt.Sprintf("i%d", t.Bits) }

// Program is an eBPF-side root.
// BpfEntry is an eBPF-side root. Other kinds only add field values (a review point): for example fentry has
// ProgramType "fentry", ContextType "bpf.FEntryContext", AttachKind "kernel-func" and an attach target field.
type BpfEntry struct {
	Symbol      string // the Go function name as is
	ProgramType string // "xdp" (the schema / ebpf.program kind)
	Attach      string // the ebpf.program attach (the sched_cls direction "ingress" / "egress" — "" for xdp)
	ContextType string // "bpf.XDPContext" (the type of the first parameter)
	AttachKind  string // "xdp-ifindex" (the attach target is decided at runtime)
	Pos         token.Position
}

// Program is the lowering unit of a root (the BpfEntry plus the closure's maps and lowering state).
type Program struct {
	BpfEntry
	kind         *ctxKind        // the context type's kind
	Nargs        int             // the argument count of the fexit target function (the directive's nargs)
	Ret          *IntType        // the fexit return type (FexitContext's R), and R of kretprobe / uretprobe
	IterMap      string          // the name of the map an iter iterates (the directive's second word)
	ExtTarget    string          // the name of the program an ext replaces into (the directive's first word)
	SOMember     string          // the member of a struct_ops program (the directive's second word)
	extFunc      *types.Func     // the `//gobpf:global` function an ext replaces (decided by checkExtPrograms)
	extArgs      []IntType       // the argument types of the function an ext replaces (the schema args — checkExtPrograms)
	TPFields     []TPField       // the tagged fields of the tracepoint event struct (ascending offset — the schema fields)
	tpEvent      *types.Named    // the tracepoint event struct (TracepointContext's E)
	tpTagged     map[string]bool // Go names of E's tagged fields (including those left out of TPFields by shape errors)
	Params       map[int]IntType // the type of the n-th kprobe argument (KprobeArg[T] — collected by lowering)
	paramPos     map[int]token.Pos
	StrParams    map[int]token.Pos // uprobe user string arguments (UprobeStr)
	PtrParams    map[int]token.Pos // kprobe pointer arguments (uint64(KprobeArg[uintptr]) — values not dereferenced)
	Binary       string            // the uprobe directive's path (generate time only — not in generated files)
	BinarySHA256 string            // the sha256 of the uprobe target binary (the schema's binary_sha256)
	// usdt: the schema semaphore ("required" / "none") and max_points (the number of points in the binary) decided from the note; USDTSpec reports whether the program
	// has USDTArg (the compiler emits the spec map `__ebpf_usdt_spec_<program>` — the generated binding declares it); usdtPoints holds the points' notes.
	USDTSemaphore string
	USDTMaxPoints int
	USDTSpec      bool
	usdtPoints    []requirements.USDTPoint
	uprobeParams  map[string][]string // uprobe target symbol → DWARF argument type spellings (excluding results — per listed symbol for uprobe_multi)
	args          map[int]tpArgDecl   // declarations of tp_btf / fentry argument i (TPArg, TPArgInt, FentryArg)
	dirPos        token.Pos
	Maps          []*BpfMap
	decl          *ast.FuncDecl
	obj           *types.Func
	body          string // the lowered body (.mlir text)
}

// Subprogram is a same-package function reachable from a program (ebpf.func "static").
type Subprogram struct {
	Symbol string
	Maps   []*BpfMap
	Pos    token.Position
	decl   *ast.FuncDecl
	obj    *types.Func
	params []vtype
	result vtype
	ok     bool   // passed the shape check
	body   string // the lowered body
	global bool   // `//gobpf:global` — ebpf.func "global" (the default is static)
	// ptrs holds the borrowed map value arguments (argument number → shape). kind is decided from the set of all call sites (subargs.go).
	ptrs map[int]*ptrParam
	// win is the packet window argument (static only, at most one). Its length and writability are decided from the set of all call sites (winargs.go).
	win *winParam
	// ctx is the kind of the program context in the first parameter (bpf-mlir v1.2.0, static only, a concrete context type). nil means none.
	ctx *ctxKind
}

// calleeCtxKinds holds the context types a subprogram can take: kinds with ops usable on the context inside a bpf-mlir callee (packet.check and windows,
// stack ids, perf.output). fexit return values and tp_btf arguments are attach-dependent reads refused in callees, so those contexts cannot be passed.
var calleeCtxKinds = map[string]bool{"XDPContext": true, "TCIngressContext": true, "TCEgressContext": true, "FentryContext": true, "KprobeContext": true, "UprobeContext": true}

// winParam is a subprogram's packet window argument (bpf-mlir v0.21.0's `!ebpf.pkt_window<N>`).
type winParam struct {
	idx    int
	obj    *types.Var
	n      int64     // the Check length at all call sites (GB013 if they differ)
	writes token.Pos // the first write in the callee (w.SetBE16 etc. — NoPos means read-only)
}

// ptrParam is a subprogram's borrowed map value argument.
type ptrParam struct {
	obj  *types.Var
	abi  SharedABI // the pointee map value type (an integer or a record)
	kind string    // "borrowed" (the caller passes a checked borrow) or "maybe_ref" (an unchecked M.Lookup(k) passed directly)
}

// mlirType returns the argument type text (`!ebpf.borrowed<T>` / `!ebpf.maybe_ref<T>`).
func (p *ptrParam) mlirType() string {
	if p.kind == "maybe_ref" {
		return "!ebpf.maybe_ref<" + p.abi.mlir() + ">"
	}
	return "!ebpf.borrowed<" + p.abi.mlir() + ">"
}

// Result is the analysis result. If Diagnostics has even one that blocks generation (Blocks), MLIR / Schema are empty.
type Result struct {
	PkgPath     string
	PkgName     string
	Dir         string
	ModuleDir   string
	Maps        []*BpfMap
	Records     []*SharedABI // records (symbol order — the same as the schema records)
	Globals     []*GlobalVar // global variables (declaration order)
	Programs    []*Program
	Graph       DomainGraph
	Diagnostics []Diagnostic
	MLIR        []byte
	Schema      []byte
	an          *analyzer // internal analysis state (only in-package tests look at it)
}

// OK reports whether no verdict blocks generation.
func (r *Result) OK() bool {
	for _, d := range r.Diagnostics {
		if d.Blocks() {
			return false
		}
	}
	return true
}

type analyzer struct {
	fset           *token.FileSet
	pkg            *packages.Package
	info           *types.Info
	dir            string
	diags          []Diagnostic
	directiveOf    map[*ast.CommentGroup]bool            // fentry program docs (where //gobpf: directives go)
	loopMode       map[ast.Stmt]string                   // for / range statements with `//gobpf:loop <mode>` ((U) if absent)
	uprobeDecl     map[*ast.FuncDecl]uprobeDirectiveInfo // uprobe directives
	iterMapOf      map[*ast.FuncDecl]string              // the map name of an iter directive
	extTargetOf    map[*ast.FuncDecl]string              // the target program name of an ext directive
	extDirPos      map[*ast.FuncDecl]token.Pos           // the position of an ext directive (for checkExtPrograms' diagnostics)
	soMemberOf     map[*ast.FuncDecl]string              // the member of a struct_ops directive
	soSeen         map[string]bool                       // `<map>/<member>` written in struct_ops directives (including signature errors — stops a cascade of missing-required errors)
	locReported    map[string]bool                       // positions already reported as GB022 (once only)
	lineInfoOff    bool                                  // generation uses --line-info=off (no GB022 check)
	maps           []*BpfMap
	mapByObj       map[*types.Var]*BpfMap
	innerByVar     map[*types.Var]*BpfMap // map-in-map: local variable of an inner handle (m in `if m := Outer.Lookup(k)`) → the inner template
	globals        []*GlobalVar           // global variables
	globalByObj    map[*types.Var]*GlobalVar
	programs       []*Program
	subs           []*Subprogram
	notPrograms    []*ast.FuncDecl // functions that take a context but are not program-shaped
	subByObj       map[*types.Func]*Subprogram
	callSums       map[*Subprogram]*callSummary   // callee summaries for the path rules of calls inside loops (callloop.go)
	rmwMemo        map[rmwKey]*rmwFacts           // per-function inputs for non-atomic RMW (rmw.go)
	globalFuncs    map[*types.Func]token.Pos      // functions marked `//gobpf:global` and the directive position (subargs.go)
	timerCallbacks map[*types.Func]*TimerCallback // functions passed to SetCallback
	urbCallbacks   map[*types.Func]*UrbCallback   // functions passed to UserRingBuf.Drain
	kernelTypes    map[*types.Named]*KernelType   // kernel local types of TPArg type arguments (nil means an error was reported)
	kernelOrder    []*KernelType                  // the order of the schema's core.kernel_types
	initGuards     []initGuard                    // the then arms of ifs on Init's status being 0
	reach          map[FuncKey]Membership         // the reachability sets (reach.go)
	userRefs       []userRef                      // references to BPF-side functions from the user side, found by checkUserSide
	curOwnerFn     *types.Func                    // the function checkUserSide is walking
	summaries      map[FuncKey]*FunctionSummary   // BPF-side function summaries (closure.go)
	closures       map[*Program]*BpfClosure       // per-program closures (closure.go)
	graph          DomainGraph
	records        []*SharedABI         // record declarations (record.go — in order found)
	recordBySymbol map[string]SharedABI // checked records (Kind 0 marks an erroneous record)
}

// Analyze analyzes the package in dir.
// Options are the options of Analyze.
type Options struct {
	// LineInfo is the generated ebpf-compile's --line-info ("auto" — the default, or "off"). With auto, an op loc outside the BTF line_info range (column ≤ 1023,
	// line ≤ 2^20) is GB022. With off, no line_info is made, so there is no check.
	LineInfo string
}

// Analyze is AnalyzeWith(dir, Options{LineInfo: "auto"}).
func Analyze(dir string) (*Result, error) { return AnalyzeWith(dir, Options{LineInfo: "auto"}) }

// AnalyzeWith analyzes the package directory and builds the generated files.
func AnalyzeWith(dir string, opt Options) (*Result, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedModule,
		Dir:        abs,
		BuildFlags: []string{"-tags=" + BuildTag},
		Tests:      false,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return nil, fmt.Errorf("gobpf: loading the package in %s: %w", abs, err)
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("gobpf: expected one package in %s, got %d", abs, len(pkgs))
	}
	a := &analyzer{
		fset: pkgs[0].Fset, pkg: pkgs[0], info: pkgs[0].TypesInfo, dir: abs,
		mapByObj: map[*types.Var]*BpfMap{}, innerByVar: map[*types.Var]*BpfMap{}, globalByObj: map[*types.Var]*GlobalVar{}, recordBySymbol: map[string]SharedABI{}, reach: map[FuncKey]Membership{}, subByObj: map[*types.Func]*Subprogram{}, timerCallbacks: map[*types.Func]*TimerCallback{}, urbCallbacks: map[*types.Func]*UrbCallback{}, kernelTypes: map[*types.Named]*KernelType{}, directiveOf: map[*ast.CommentGroup]bool{}, uprobeDecl: map[*ast.FuncDecl]uprobeDirectiveInfo{}, iterMapOf: map[*ast.FuncDecl]string{}, extTargetOf: map[*ast.FuncDecl]string{}, extDirPos: map[*ast.FuncDecl]token.Pos{}, soMemberOf: map[*ast.FuncDecl]string{}, soSeen: map[string]bool{}, locReported: map[string]bool{}, lineInfoOff: opt.LineInfo == "off",
	}
	res := &Result{PkgPath: a.pkg.PkgPath, PkgName: a.pkg.Name, Dir: abs, an: a}
	if a.pkg.Module != nil {
		res.ModuleDir = a.pkg.Module.Dir
	}
	// Go type check errors (including references to generated identifiers) stop with GB000.
	// go list errors (summaries without positions) are dropped as duplicates when positioned type check errors exist.
	positioned := false
	for _, e := range a.pkg.Errors {
		if e.Pos != "" && e.Pos != "-" {
			positioned = true
		}
	}
	for _, e := range a.pkg.Errors {
		if positioned && (e.Pos == "" || e.Pos == "-") {
			continue
		}
		a.diags = append(a.diags, Diagnostic{Verdict: Rejected, Code: GB000TypeCheck, Pos: a.errPos(e.Pos), Msg: e.Msg})
	}
	if len(a.diags) > 0 || a.info == nil {
		sortDiagnostics(a.diags)
		res.Diagnostics = a.diags
		return res, nil
	}
	a.checkReserved()
	a.collectMaps()
	a.checkMapSizeLimit() // bpf-mlir v0.17.0's K9 (the BTF limit of map definitions), first with Go positions
	a.checkSpecialMaps()  // lock / timer records only as Array values
	a.collectPrograms()
	a.checkStructOps()      // the member set of struct_ops maps (duplicates, missing required members)
	a.checkUprobeBinaries() // the uprobe target binary (sha256, symbol, calling convention, DWARF) — checked at generate time
	a.checkUSDTBinaries()   // the usdt binary notes (points, semaphore, point count)
	a.checkGlobalNames()
	a.collectGlobalDirectives() // `//gobpf:global` (subprogram linkage — marks docs before checkStrayDirectives)
	a.collectLoopDirectives()   // `//gobpf:loop backedge` onto the for on the next line (marks docs before checkStrayDirectives)
	a.checkStrayDirectives()    // //gobpf: directives only right before fentry programs
	a.computeDomains()
	a.checkExtPrograms()      // ext targets (a same-package program, a global function it calls, identical signatures — after the domain edges)
	a.collectTimerCallbacks() // SetCallback callbacks (not subprograms) and ifs on Init's status
	a.collectUrbCallbacks()   // UserRingBuf.Drain callbacks (not subprograms)
	a.collectTailSlots()      // `var _ = bpf.TailSlot(&M, slot, Prog)` (after domains — TailSlot inside eBPF-side functions is left to checkEBPFSide's GB003)
	a.computeUserReach()
	a.reportNotPrograms()
	a.checkUserSide()
	a.checkSharedReach()
	a.checkEBPFSide()
	a.checkRecursion()
	a.checkExports()
	a.buildSummaries()
	a.buildClosures()
	a.checkSpecialMapUsers() // lock / timer maps in kprobe / uprobe programs
	capBad := a.checkCapabilities()
	a.collectSubprograms()
	a.checkReservedNames() // the `__ebpf_` prefix is reserved for the compiler (bpf-mlir v1.4.0's outlined __ebpf_present_<function>_<n>)
	a.resolvePtrParams()   // borrowed argument shapes (over all call sites), the global mark, callee nil check rules
	a.resolveWinParams()   // window argument length and writability (over all call sites), static only, no forwarding
	// Skip lowering only for functions that are the source of a capability error (those that themselves need a capability not provided), and run shape checks on the rest —
	// report capability and shape errors in one pass without reporting the same syntax twice. Callers look only at the call shape (nothing is emitted if there are errors).
	for _, s := range a.subs {
		if s.ok && !capBad[keyOf(s.obj)] {
			a.guardLowering(s.Symbol, s.decl.Name.Pos(), func() { a.lowerSubprogram(s) })
		}
	}
	for _, p := range a.programs {
		if !capBad[keyOf(p.obj)] {
			a.guardLowering(p.Symbol, p.decl.Name.Pos(), func() { a.lowerProgram(p) })
			a.checkTPArgs(p) // missing argument declarations
		}
	}
	for _, cb := range a.sortedCallbacks() { // after programs (SetCallback binds the map)
		a.guardLowering(cb.Symbol, cb.decl.Name.Pos(), func() { a.lowerCallback(cb) })
	}
	for _, cb := range a.sortedUrbCallbacks() { // after programs (Drain binds the map)
		a.guardLowering(cb.Symbol, cb.decl.Name.Pos(), func() { a.lowerUrbCallback(cb) })
	}
	a.checkUprobeParams() // checks UprobeArg / UprobeStr types collected by lowering against DWARF
	a.checkUSDTParams()   // checks USDTArg types collected by lowering against the note's point argument specs
	a.buildGraph()
	sortDiagnostics(a.diags)
	res.Maps, res.Programs, res.Graph, res.Diagnostics, res.Globals = a.maps, a.programs, a.graph, a.diags, a.globals
	res.Records = sortedRecords(a.records)
	if res.OK() {
		res.MLIR = emitModule(a.subs, a.programs, a.sortedCallbacks(), a.sortedUrbCallbacks())
		if bad := verifyBPFWorld(string(res.MLIR)); len(bad) > 0 {
			// The verify-bpf-world exit check — an op outside the allowed set stops as a frontend bug.
			a.diags = append(a.diags, Diagnostic{Verdict: Unknown, Code: GB015InternalEmitter, Msg: bpfWorldError(bad)})
			res.Diagnostics, res.MLIR = a.diags, nil
			return res, nil
		}
		sch, err := buildSchema(a.maps, a.records, a.programs, a.globals, a.kernelOrder)
		if err != nil {
			return nil, err
		}
		res.Schema = sch
	}
	return res, nil
}

// --- positions -------------------------------------------------------------------

func (a *analyzer) position(p token.Pos) token.Position {
	pos := a.fset.Position(p)
	if rel, err := filepath.Rel(a.dir, pos.Filename); err == nil {
		pos.Filename = rel
	}
	return pos
}

func (a *analyzer) errPos(s string) token.Position {
	// packages.Error's Pos is a "file:line:col" string.
	var pos token.Position
	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		pos.Filename = parts[0]
		fmt.Sscanf(parts[1], "%d", &pos.Line)
		fmt.Sscanf(parts[2], "%d", &pos.Column)
		if rel, err := filepath.Rel(a.dir, pos.Filename); err == nil {
			pos.Filename = rel
		}
	} else {
		pos.Filename = s
	}
	return pos
}

func (a *analyzer) report(v Verdict, c Code, p token.Pos, path []string, format string, args ...any) {
	a.diags = append(a.diags, Diagnostic{Verdict: v, Code: c, Pos: a.position(p), Path: path, Msg: fmt.Sprintf(format, args...)})
}

// files returns the package files sorted by name (for a deterministic walk).
func (a *analyzer) files() []*ast.File {
	fs := append([]*ast.File(nil), a.pkg.Syntax...)
	sort.Slice(fs, func(i, j int) bool { return a.fset.File(fs[i].Pos()).Name() < a.fset.File(fs[j].Pos()).Name() })
	return fs
}

// --- reserved names -----------------------------------------------------------------

func (a *analyzer) checkReserved() {
	var ids []*ast.Ident
	for id, obj := range a.info.Defs {
		if obj != nil && strings.HasPrefix(id.Name, ReservedPrefix) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Pos() < ids[j].Pos() })
	for _, id := range ids {
		a.report(Rejected, GB007ReservedName, id.Pos(), nil, "identifier %q uses the prefix %q reserved for gobpf's generated file", id.Name, ReservedPrefix)
	}
}

// --- map declarations -----------------------------------------------------------------

// arrayInstance returns K and V if t is an instance of bpf.Array[K, V].
func arrayInstance(t types.Type) (k, v types.Type, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || (n.Origin().Obj().Name() != "Array" && n.Origin().Obj().Name() != "PerCPUArray") {
		return nil, nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 2 {
		return nil, nil, false
	}
	return args.At(0), args.At(1), true
}

func intTypeOf(t types.Type) (IntType, bool) {
	b, ok := t.Underlying().(*types.Basic)
	if !ok {
		return IntType{}, false
	}
	switch b.Kind() {
	case types.Uint8:
		return IntType{8, false}, true
	case types.Uint16:
		return IntType{16, false}, true
	case types.Uint32:
		return IntType{32, false}, true
	case types.Uint64:
		return IntType{64, false}, true
	case types.Int8:
		return IntType{8, true}, true
	case types.Int16:
		return IntType{16, true}, true
	case types.Int32:
		return IntType{32, true}, true
	case types.Int64:
		return IntType{64, true}, true
	}
	return IntType{}, false
}

func (a *analyzer) collectMaps() {
	for _, f := range a.files() {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					obj, _ := a.info.Defs[name].(*types.Var)
					if obj == nil {
						continue
					}
					if sec, elem, isGlobal := globalInstance(obj.Type()); isGlobal {
						a.collectGlobal(obj, name, vs, i, sec, elem)
						continue
					}
					if isBPFNamed(obj.Type(), "StackTrace") || isBPFNamed(obj.Type(), "StackBuildID") {
						a.collectStackTrace(obj, name, vs, i, isBPFNamed(obj.Type(), "StackBuildID"))
						continue
					}
					if pv, isPerf := perfInstance(obj.Type()); isPerf {
						a.collectPerf(obj, name, vs, i, pv)
						continue
					}
					if kind, isRedir := redirectMapKinds[namedBPF(obj.Type())]; isRedir {
						a.collectDevMap(obj, name, vs, i, kind) // also cpumap, devmap_hash, xskmap
						continue
					}
					if kind, isSock := sockMapKinds[namedBPF(obj.Type())]; isSock {
						a.collectSockMap(obj, name, vs, i, kind)
						continue
					}
					if isBPFNamed(obj.Type(), "TCPCongestionOps") {
						a.collectStructOps(obj, name, vs, i)
						continue
					}
					if isBPFNamed(obj.Type(), "ProgArray") {
						a.collectProgArray(obj, name, vs, i)
						continue
					}
					if kind, sv, isStorage := storageInstance(obj.Type()); isStorage {
						a.collectStorage(obj, name, vs, i, kind, sv)
						continue
					}
					if kind, okT, kT, vT, isMIM := mapInMapInstance(obj.Type()); isMIM {
						a.collectMapInMap(obj, name, vs, i, kind, okT, kT, vT)
						continue
					}
					if kind, kv, isKeyless := keylessInstance(obj.Type()); isKeyless {
						a.collectKeyless(obj, name, vs, i, kind, kv)
						continue
					}
					if lv, bpfP, isLPM := lpmInstance(obj.Type()); isLPM {
						a.collectLPM(obj, name, vs, i, lv, bpfP)
						continue
					}
					if kind, hk, hv, isHash := hashInstance(obj.Type()); isHash {
						a.collectHash(obj, name, vs, i, kind, hk, hv)
						continue
					}
					if ev, isRB := ringbufInstance(obj.Type()); isRB {
						a.collectRingBuf(obj, name, vs, i, ev)
						continue
					}
					if sv, isURB := userRingBufInstance(obj.Type()); isURB {
						a.collectUserRingBuf(obj, name, vs, i, sv)
						continue
					}
					k, v, isArr := arrayInstance(obj.Type())
					if !isArr {
						continue
					}
					kind := "array"
					if obj.Type().(*types.Named).Origin().Obj().Name() == "PerCPUArray" {
						kind = "percpu_array"
					}
					m := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj}
					ki, okK := intTypeOf(k)
					if !okK {
						a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: the key must be a fixed-width integer", obj.Name())
						continue
					}
					m.Key = sharedABIOfInt(k, ki)
					// The value is a fixed-width integer or a record (bpf.Array's V is any — the shape is checked here).
					if vi, okV := intTypeOf(v); okV {
						if vi.Bits < 32 {
							a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: an integer value must be 32 or 64 bit, got %s (wrap narrower values in a record)", obj.Name(), v)
							continue
						}
						m.Value = sharedABIOfInt(v, vi)
					} else if rv, okR := a.recordOf(v, name.Pos(), "map "+obj.Name()+" value"); okR {
						m.Value = rv
					} else {
						continue
					}
					if len(vs.Values) != len(vs.Names) {
						a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s needs an initializer bpf.Array[K, V]{MaxEntries: N} (MaxEntries is required)", obj.Name())
						continue
					}
					if !a.mapInit(m, vs.Values[i]) {
						continue
					}
					a.maps = append(a.maps, m)
					a.mapByObj[obj] = m
				}
			}
		}
	}
}

func (a *analyzer) mapInit(m *BpfMap, e ast.Expr) bool {
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		a.report(Rejected, GB009MapDeclShape, e.Pos(), nil, "map %s: the initializer must be a composite literal bpf.Array[K, V]{MaxEntries: N}", m.Symbol)
		return false
	}
	found := false
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		key, _ := kv.Key.(*ast.Ident)
		if !ok || key == nil || key.Name != "MaxEntries" {
			a.report(Rejected, GB009MapDeclShape, el.Pos(), nil, "map %s: only the field MaxEntries may be set", m.Symbol)
			return false
		}
		tv := a.info.Types[kv.Value]
		if tv.Value == nil {
			a.report(Rejected, GB006NonConstant, kv.Value.Pos(), nil, "map %s: MaxEntries must be a constant", m.Symbol)
			return false
		}
		n, exact := constUint64(tv)
		if !exact || n == 0 {
			a.report(Rejected, GB009MapDeclShape, kv.Value.Pos(), nil, "map %s: MaxEntries must be a positive constant", m.Symbol)
			return false
		}
		m.MaxEntries, m.maxPos, found = n, kv.Value.Pos(), true
	}
	if !found {
		a.report(Rejected, GB009MapDeclShape, cl.Pos(), nil, "map %s: MaxEntries is required", m.Symbol)
		return false
	}
	return true
}

// --- collecting programs -------------------------------------------------------------------

// isXDPContextPtr reports whether t is a pointer to a program context (not only XDP but every context kind — the name is kept for compatibility).
func isXDPContextPtr(t types.Type) bool { return ctxKindOf(t) != nil }

func isBPFNamed(t types.Type, name string) bool {
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == bpfPkg && n.Obj().Name() == name
}

func mentionsContext(sig *types.Signature) bool {
	for i := 0; i < sig.Params().Len(); i++ {
		if isContextType(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

func (a *analyzer) collectPrograms() {
	for _, f := range a.files() {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			obj, _ := a.info.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			sig := obj.Type().(*types.Signature)
			if !mentionsContext(sig) {
				continue
			}
			var ck *ctxKind
			if sig.Params().Len() == 1 {
				ck = ctxKindOf(sig.Params().At(0).Type())
			}
			resultOK := ck != nil && ((ck.Action == "" && sig.Results().Len() == 0) || (ck.Action != "" && sig.Results().Len() == 1 && isBPFNamed(sig.Results().At(0).Type(), ck.Action)))
			if ck != nil && ck.Kind == "ext" { // the result is the replaced function's result type (an integer — checkExtPrograms checks identity)
				resultOK = false
				if sig.Results().Len() == 1 {
					_, resultOK = intTypeOf(sig.Results().At(0).Type())
				}
			}
			if ck != nil && ck.Kind == "struct_ops" { // the result follows the member table (none or uint32 — structOpsDirective checks it)
				resultOK = sig.Results().Len() == 0
				if sig.Results().Len() == 1 {
					_, resultOK = intTypeOf(sig.Results().At(0).Type())
				}
			}
			shapeOK := fd.Recv == nil && sig.TypeParams() == nil && ck != nil && resultOK && fd.Body != nil
			if !shapeOK {
				a.notPrograms = append(a.notPrograms, fd) // reported after domains (GB013 if called from a program — a review point)
				continue
			}
			ck = multiKindFor(fd, ck) // `//gobpf:kprobe_multi …` is the multi kind of the same context type
			attach := ck.Attach
			nargs, ret := 0, (*IntType)(nil)
			if isTracingProgramKind(ck.Kind) {
				if fd.Doc != nil {
					a.directiveOf[fd.Doc] = true // a tracing program doc — tracingTarget reports shape errors (not twice via checkStrayDirectives)
				}
				// The directive shape error was already reported (GB008 — generation stops). Still register it as a program (so API use in the body does not cascade into user-side GB003).
				attach, nargs, _ = a.tracingTarget(fd, ck.Kind)
			}
			if ck.Kind == "fexit" || isRetprobeKind(ck.Kind) {
				// The return type is the context type argument R (an 8 / 16 / 32 / 64-bit integer by the type constraint; the same for kretprobe / uretprobe).
				if n, ok := sig.Params().At(0).Type().(*types.Pointer).Elem().(*types.Named); ok && n.TypeArgs().Len() == 1 {
					if it, ok := intTypeOf(n.TypeArgs().At(0)); ok {
						ret = &it
					}
				}
				if ret == nil {
					a.report(Rejected, GB008ProgramShape, fd.Name.Pos(), []string{fd.Name.Name}, "the %s program %s: the return type in *bpf.%s[R] must be an 8 / 16 / 32 / 64-bit integer", ck.Kind, fd.Name.Name, ck.Type)
				}
			}
			if ck.Kind == "fmod_ret" {
				ret = &IntType{Bits: 32, Signed: true} // the result is bpf.FmodRet (int32 — the i32 of the requirements' retsig)
			}
			if ck.Kind == "ext" { // the Go integer type of the result (the ebpf.return width)
				it, _ := intTypeOf(sig.Results().At(0).Type())
				ret = &it
			}
			soMember := ""
			if ck.Kind == "struct_ops" { // split the kind row by the member result (void is done, uint32 is ebpf.return)
				soMember = a.soMemberOf[fd]
				if mem, ok := tcpCongestionMembers[soMember]; ok {
					ck = structOpsKind(ck, mem)
					ret = mem.ret
				} else if sig.Results().Len() == 1 { // the directive error was already reported — lower the body with its result type (no cascade into return errors)
					it, _ := intTypeOf(sig.Results().At(0).Type())
					ck, ret = structOpsKind(ck, structOpsMember{ret: &it}), &it
				}
			}
			p := &Program{BpfEntry: BpfEntry{Symbol: obj.Name(), ProgramType: ck.Kind, Attach: attach, ContextType: "bpf." + ck.Type, AttachKind: ck.AttachKind, Pos: a.position(fd.Name.Pos())}, decl: fd, obj: obj, kind: ck, Nargs: nargs, Ret: ret, IterMap: a.iterMapOf[fd], ExtTarget: a.extTargetOf[fd], SOMember: soMember}
			if ck.Kind == "tracepoint" {
				a.tracepointEvent(p, sig.Params().At(0).Type().(*types.Pointer).Elem())
			}
			a.programs = append(a.programs, p)
		}
	}
}

// --- domain (roots + reachability) -----------------------------------------------------------------

func (a *analyzer) funcDecls() map[*types.Func]*ast.FuncDecl {
	out := map[*types.Func]*ast.FuncDecl{}
	for _, f := range a.files() {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if obj, _ := a.info.Defs[fd.Name].(*types.Func); obj != nil {
					out[obj] = fd
				}
			}
		}
	}
	return out
}

// samePkgFunc returns the function if e refers to a top-level function of the same package.
func (a *analyzer) samePkgFunc(id *ast.Ident) *types.Func {
	fn, ok := a.info.Uses[id].(*types.Func)
	if !ok || fn.Pkg() != a.pkg.Types {
		return nil
	}
	if sig := fn.Type().(*types.Signature); sig.Recv() != nil {
		return nil
	}
	return fn
}

func (a *analyzer) computeDomains() {
	decls := a.funcDecls()
	var work []*types.Func
	for _, p := range a.programs {
		a.reach[keyOf(p.obj)] |= MemBPF
		a.graph.Nodes = append(a.graph.Nodes, GraphNode{Func: p.Symbol, Domain: "ebpf", Root: true, Kind: p.ProgramType, Pos: posString(p.Pos)})
		work = append(work, p.obj)
	}
	// Same-package functions reachable from a root are also on the eBPF side (they become subprograms; reachability is computed the same way).
	for len(work) > 0 {
		fn := work[0]
		work = work[1:]
		fd := decls[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			callee := a.samePkgFunc(id)
			if callee == nil {
				return true
			}
			a.graph.Edges = append(a.graph.Edges, GraphEdge{From: fn.Name(), To: callee.Name(), Kind: "call", Pos: posString(a.position(id.Pos()))})
			if !a.isBPF(callee) {
				a.reach[keyOf(callee)] |= MemBPF
				a.graph.Nodes = append(a.graph.Nodes, GraphNode{Func: callee.Name(), Domain: "ebpf", Pos: posString(a.position(decls[callee].Name.Pos()))})
				work = append(work, callee)
			}
			return true
		})
	}
	var rest []*types.Func
	for fn := range decls {
		if !a.isBPF(fn) {
			rest = append(rest, fn)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Pos() < rest[j].Pos() })
	for _, fn := range rest {
		a.graph.Nodes = append(a.graph.Nodes, GraphNode{Func: fn.Name(), Domain: "user", Pos: posString(a.position(decls[fn].Name.Pos()))})
	}
}

// --- user-space side checks -------------------------------------------------------------

// walkWithStack walks the AST keeping the stack of parents.
func walkWithStack(root ast.Node, f func(n ast.Node, stack []ast.Node)) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		f(n, stack)
		stack = append(stack, n)
		return true
	})
}

func (a *analyzer) checkUserSide() {
	for _, f := range a.files() {
		for _, d := range f.Decls {
			owner := "(package-level)"
			a.curOwnerFn = nil
			if fd, ok := d.(*ast.FuncDecl); ok {
				obj, _ := a.info.Defs[fd.Name].(*types.Func)
				if a.isBPF(obj) {
					continue
				}
				owner = fd.Name.Name
				a.curOwnerFn = obj
			}
			walkWithStack(d, func(n ast.Node, stack []ast.Node) {
				id, ok := n.(*ast.Ident)
				if !ok {
					return
				}
				obj := a.info.Uses[id]
				if obj == nil {
					return
				}
				// References to eBPF-side functions: allowed only as arguments of programValueTakers (gobpf.AttachXDP etc.).
				if fn, isFn := obj.(*types.Func); isFn && a.isBPF(fn) {
					a.userRefToEBPF(owner, id, fn, stack)
					return
				}
				// Misuse of map variables (reassignment, address-of).
				if v, isVar := obj.(*types.Var); isVar {
					if m := a.mapByObj[v]; m != nil {
						a.checkMapVarUse(owner, id, m, stack)
						// A review point: a user-side Put on a map of timer records stops a running timer (a bpf-mlir finding).
						if sel, ok := parent(stack, 1).(*ast.SelectorExpr); ok && sel.X == ast.Expr(id) && sel.Sel.Name == "Put" &&
							m.Value.Kind == ABIRecord && m.Value.Record.Special != nil && m.Value.Record.Special.Type.Kind == ABITimer {
							a.report(Rejected, GB026LockTimerShape, sel.Sel.Pos(), []string{owner}, "%s.Put would stop a running timer — the kernel cancels the bpf.Timer %s.%s of an element updated from user space; the entries of an array start zeroed, so write the other fields on the eBPF side", m.Symbol, m.Value.Record.Symbol, m.Value.Record.Special.GoName)
						}
					}
					if g := a.globalByObj[v]; g != nil {
						a.checkGlobalVarUse(owner, id, g, stack)
					}
					return
				}
				if !inAPIPackage(obj) {
					return
				}
				e, known := lookupAPI(obj)
				switch {
				case !known:
					a.report(Unknown, GB002UnsupportedCall, id.Pos(), []string{owner}, "%s is not in gobpf's API table", qualifiedName(obj))
				case e.side == sideEBPF:
					a.report(Rejected, GB003CrossDomainUse, id.Pos(), []string{owner, id.Name},
						"%s is an eBPF-side operation and cannot be used in user space (func %s is not reachable from a program)", qualifiedName(obj), owner)
				default:
					a.checkNotMethodValue(owner, id, obj, stack)
				}
			})
		}
	}
}

// checkEBPFSide looks at every identifier in eBPF-side function bodies and stops user-space APIs, the gobpf runtime and bpf identifiers not in the table,
// regardless of statement shape (the eBPF half of the two-way check, separate from lowering's shape checks).
func (a *analyzer) checkEBPFSide() {
	decls := a.funcDecls()
	var fns []*types.Func
	for fn := range decls {
		if a.isBPF(fn) {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		ast.Inspect(decls[fn].Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj := a.info.Uses[id]
			if !inAPIPackage(obj) {
				return true
			}
			e, known := lookupAPI(obj)
			switch {
			case !known:
				a.report(Unknown, GB002UnsupportedCall, id.Pos(), []string{fn.Name()}, "%s is not in gobpf's API table", qualifiedName(obj))
			case e.side == sideUser:
				a.report(Rejected, GB003CrossDomainUse, id.Pos(), []string{fn.Name(), id.Name},
					"%s is a user-space operation and cannot be used on the eBPF side (func %s is reachable from a program)", qualifiedName(obj), fn.Name())
			}
			return true
		})
	}
}

func parent(stack []ast.Node, up int) ast.Node {
	if len(stack) < up {
		return nil
	}
	return stack[len(stack)-up]
}

// checkNotMethodValue stops a method used as a value without being called (Counts.Get assigned to a variable).
func (a *analyzer) checkNotMethodValue(owner string, id *ast.Ident, obj types.Object, stack []ast.Node) {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Type().(*types.Signature).Recv() == nil {
		return
	}
	sel, _ := parent(stack, 1).(*ast.SelectorExpr)
	call, _ := parent(stack, 2).(*ast.CallExpr)
	if sel == nil || call == nil || call.Fun != sel {
		a.report(Unknown, GB004UnknownEdge, id.Pos(), []string{owner}, "method value %s cannot be followed statically; call it directly", qualifiedName(obj))
	}
}

func (a *analyzer) userRefToEBPF(owner string, id *ast.Ident, fn *types.Func, stack []ast.Node) {
	if call, ok := parent(stack, 1).(*ast.CallExpr); ok {
		if call.Fun == ast.Expr(id) {
			a.userRefs = append(a.userRefs, userRef{Owner: owner, OwnerFn: a.curOwnerFn, Target: fn})
			a.report(Rejected, GB003CrossDomainUse, id.Pos(), []string{owner, fn.Name()},
				"%s is an eBPF-side function (a program or reachable from one) and cannot be called from user space", fn.Name())
			return
		}
		// A program in a prog_array slot declaration (collectTailSlots checks the shape).
		if a.isTailSlotCall(call) && len(call.Args) == 3 && ast.Unparen(call.Args[2]) == ast.Expr(id) {
			a.graph.Edges = append(a.graph.Edges, GraphEdge{From: owner, To: fn.Name(), Kind: "funcvalue", Via: "bpf.TailSlot", Pos: posString(a.position(id.Pos()))})
			return
		}
		if via := a.programTaker(call); via != "" {
			a.graph.Edges = append(a.graph.Edges, GraphEdge{From: owner, To: fn.Name(), Kind: "funcvalue", Via: via, Pos: posString(a.position(id.Pos()))})
			return
		}
	}
	a.userRefs = append(a.userRefs, userRef{Owner: owner, OwnerFn: a.curOwnerFn, Target: fn})
	a.report(Unknown, GB004UnknownEdge, id.Pos(), []string{owner, fn.Name()},
		"the eBPF-side function %s is used as a value; only gobpf.AttachXDP, gobpf.AttachTCX, gobpf.AttachFentry, gobpf.AttachFexit and Objects.Program may take it", fn.Name())
}

// programValueTakers holds the gobpf APIs that may take a program function value as an argument (a table).
var programValueTakers = map[string]bool{
	gobpfPkg + ".AttachXDP":          true,
	gobpfPkg + ".AttachTCX":          true, // added late (missed because _test.go files are outside the frontend's analysis)
	gobpfPkg + ".AttachFentry":       true,
	gobpfPkg + ".AttachFexit":        true,
	gobpfPkg + ".AttachFsession":     true,
	gobpfPkg + ".AttachIter":         true,
	gobpfPkg + ".AttachKprobe":       true,
	gobpfPkg + ".AttachUprobe":       true,
	gobpfPkg + ".AttachTPBTF":        true,
	gobpfPkg + ".AttachTracepoint":   true,
	gobpfPkg + ".AttachRawTP":        true,
	gobpfPkg + ".AttachKretprobe":    true,
	gobpfPkg + ".AttachLSM":          true,
	gobpfPkg + ".AttachPerfEvent":    true,
	gobpfPkg + ".AttachKsyscall":     true,
	gobpfPkg + ".AttachKprobeMulti":  true,
	gobpfPkg + ".AttachUprobeMulti":  true,
	gobpfPkg + ".AttachUSDT":         true,
	gobpfPkg + ".AttachSockmap":      true,
	gobpfPkg + ".AttachUretprobe":    true,
	gobpfPkg + ".AttachCgroup":       true,
	gobpfPkg + ".AttachSocketFilter": true,
	gobpfPkg + ".AttachNetNs":        true,
	gobpfPkg + ".AttachReuseport":    true,
	gobpfPkg + ".AttachNetfilter":    true,
	gobpfPkg + ".AttachLWTRoute":     true,
	gobpfPkg + ".AttachSeg6Local":    true,
	gobpfPkg + ".AttachFmodRet":      true,

	gobpfPkg + ".AttachRawTPWritable": true,
	gobpfPkg + ".AttachKprobeSession": true,
	gobpfPkg + ".RunSyscall":          true,
	gobpfPkg + ".AttachExt":           true,

	gobpfPkg + ".WithUprobeTarget": true, // Load input — a program function and a target path
	gobpfPkg + ".Objects.Program":  true,
}

// programTaker returns the API name if call is a call of an API that may take a program function value.
func (a *analyzer) programTaker(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	obj := a.info.Uses[sel.Sel]
	if obj == nil || !programValueTakers[qualifiedName(obj)] {
		return ""
	}
	return strings.TrimPrefix(qualifiedName(obj), gobpfPkg[:strings.LastIndex(gobpfPkg, "/")+1])
}

// checkMapVarUse checks that a map variable is used only as a method receiver (it stops reassignment, taking the address and copying the value).
func (a *analyzer) checkMapVarUse(owner string, id *ast.Ident, m *BpfMap, stack []ast.Node) {
	if sel, ok := parent(stack, 1).(*ast.SelectorExpr); ok && sel.X == ast.Expr(id) {
		return
	}
	// Ring buffer reader: the address may be taken only as the argument of `gobpf.NewReader(&Events)`.
	if u, ok := parent(stack, 1).(*ast.UnaryExpr); ok && u.Op == token.AND && m.Kind == "ringbuf" {
		if call, ok := parent(stack, 2).(*ast.CallExpr); ok && len(call.Args) == 1 && call.Args[0] == ast.Expr(u) && a.isGobpfFunc(call, "NewReader") {
			return
		}
	}
	// User ring buffer writer: the address may be taken only as the argument of `gobpf.NewUserRingWriter(&In)`.
	if u, ok := parent(stack, 1).(*ast.UnaryExpr); ok && u.Op == token.AND && m.Kind == "user_ringbuf" {
		if call, ok := parent(stack, 2).(*ast.CallExpr); ok && len(call.Args) == 1 && call.Args[0] == ast.Expr(u) && a.isGobpfFunc(call, "NewUserRingWriter") {
			return
		}
	}
	// Perf event reader: the address may be taken only as the first argument of `gobpf.NewPerfReader(&Events, pages)`.
	if u, ok := parent(stack, 1).(*ast.UnaryExpr); ok && u.Op == token.AND && m.Kind == "perf_event_array" {
		if call, ok := parent(stack, 2).(*ast.CallExpr); ok && len(call.Args) == 2 && call.Args[0] == ast.Expr(u) && a.isGobpfFunc(call, "NewPerfReader") {
			return
		}
	}
	// prog_array slot declaration: the address may be taken only as the first argument of `bpf.TailSlot(&M, …)`.
	if u, ok := parent(stack, 1).(*ast.UnaryExpr); ok && m.Kind == "prog_array" {
		if call, ok := parent(stack, 2).(*ast.CallExpr); ok && a.isTailSlotMapArg(u, call) {
			return
		}
	}
	// gobpf's generated files are excluded, so anything here is direct use in user code.
	a.report(Rejected, GB009MapDeclShape, id.Pos(), []string{owner},
		"map variable %s may only be used as the receiver of its methods (no reassignment, address or copy)", m.Symbol)
}

// --- constants -------------------------------------------------------------------

func constUint64(tv types.TypeAndValue) (uint64, bool) {
	if tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Uint64Val(tv.Value)
}

// --- subprograms ---

// collectSubprograms collects non-root eBPF-side functions in declaration order and checks their shape (GB013).
// reservedPrefix is the prefix eBPF-side function names cannot use (programs, subprograms, timer callbacks — they are the BPF symbol names themselves).
// bpf-mlir v1.4.0 outlines reservation presence checks above a threshold into static functions `__ebpf_present_<function>_<n>` (ebpf-compile errors if the module
// already has that name). The `__ebpf_` prefix is reserved whether or not it collides (matching spinel's SB007 and mojo — a review point).
const reservedPrefix = "__ebpf_"

// checkReservedNames stops the reserved prefix in eBPF-side function names with GB013 (positioned at the function name).
func (a *analyzer) checkReservedNames() {
	decls := a.funcDecls()
	var fns []*types.Func
	for fn := range decls {
		if a.isBPF(fn) && strings.HasPrefix(fn.Name(), reservedPrefix) {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		a.report(Rejected, GB013SubprogramShape, decls[fn].Name.Pos(), []string{fn.Name()}, "the eBPF-side function name %s starts with %s, which is reserved for functions the compiler adds (bpf-mlir outlines large ring buffer reservations into static functions named __ebpf_present_<function>_<n>) — rename the function", fn.Name(), reservedPrefix)
	}
}

func (a *analyzer) collectSubprograms() {
	decls := a.funcDecls()
	var fns []*types.Func
	roots := map[*types.Func]bool{}
	for _, p := range a.programs {
		roots[p.obj] = true
	}
	for fn := range decls {
		if a.timerCallbacks[fn] != nil || a.urbCallbacks[fn] != nil {
			continue // timer callbacks (lowered as ebpf.timer.callback) and drain callbacks (ebpf.user_ringbuf.callback)
		}
		if a.isBPF(fn) && !roots[fn] {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		fd := decls[fn]
		s := &Subprogram{Symbol: fn.Name(), Pos: a.position(fd.Name.Pos()), decl: fd, obj: fn, ok: true}
		a.subs = append(a.subs, s)
		a.subByObj[fn] = s
		sig := fn.Type().(*types.Signature)
		bad := func(p token.Pos, format string, args ...any) {
			a.report(Rejected, GB013SubprogramShape, p, []string{fn.Name()}, format, args...)
			s.ok = false
		}
		if fd.Recv != nil || sig.TypeParams() != nil || fd.Body == nil {
			bad(fd.Name.Pos(), "subprogram %s must be a plain top-level function (no receiver, no type parameters)", fn.Name())
			continue
		}
		if sig.Params().Len() > 5 {
			bad(fd.Name.Pos(), "subprogram %s has %d parameters; at most 5 integers (BPF-to-BPF calls pass arguments in registers)", fn.Name(), sig.Params().Len())
		}
		for i := 0; i < sig.Params().Len(); i++ {
			pv := sig.Params().At(i)
			if ck := ctxKindOf(pv.Type()); ck != nil { // a program context parameter (bpf-mlir v1.2.0)
				_, isGlobal := a.globalFuncs[fn]
				switch {
				case !calleeCtxKinds[ck.Type]:
					bad(fd.Name.Pos(), "subprogram %s parameter %s: the %s context cannot be passed to a subprogram — a callee may use the context only for ctx.Check and window reads, stack ids and perf output (bpf-mlir); read the %s value in the program and pass it as an integer", fn.Name(), pv.Name(), ck.Kind, ck.Kind)
				case i != 0:
					bad(fd.Name.Pos(), "subprogram %s parameter %s: the program context must be the first parameter (bpf-mlir refuses a context after a map handle)", fn.Name(), pv.Name())
				case isGlobal:
					bad(fd.Name.Pos(), "global subprogram %s takes the program context — only a static subprogram can (the kernel verifies a global function on its own); drop //gobpf:global", fn.Name())
				default:
					s.ctx = ck
				}
				s.params = append(s.params, vtype{}) // keep the position — the type is ctx
				continue
			}
			if isBPFNamed(pv.Type(), "Window") { // a packet window parameter (the window of the caller's Check)
				if s.win != nil {
					bad(fd.Name.Pos(), "subprogram %s has more than one packet window parameter; at most one", fn.Name())
					continue
				}
				s.win = &winParam{idx: i, obj: pv}
				s.params = append(s.params, vtype{}) // keep the position — the type is win
				continue
			}
			if abi, isRef := a.mapValuePointee(pv.Type()); isRef { // a borrowed map value parameter (writes allowed too)
				if len(s.ptrs) == 1 {
					bad(fd.Name.Pos(), "subprogram %s has more than one pointer parameter; at most one (a subprogram takes one checked map value; a program may hold two borrows at once but passes only one of them to a call — pass the other value as an integer)", fn.Name())
					continue
				}
				if s.ptrs == nil {
					s.ptrs = map[int]*ptrParam{}
				}
				s.ptrs[i] = &ptrParam{obj: pv, abi: abi}
				s.params = append(s.params, vtype{}) // keep the position — the type is ptrs[i]
				continue
			}
			t, ok := goType(pv.Type())
			if !ok {
				what := pv.Type().String()
				if isXDPContextPtr(pv.Type()) {
					what = "the program context"
				} else if _, isPtr := pv.Type().(*types.Pointer); isPtr {
					what = "a pointer to something other than a map value (only *T for a map's value type T — an integer or a record — can be passed; the context, reservations and other pointers are not in bpf-mlir's subprogram contract)"
				}
				bad(fd.Name.Pos(), "subprogram %s parameter %s: %s cannot be passed to a subprogram (integers and bool, a map value *T, or a packet window bpf.Window)", fn.Name(), pv.Name(), what)
				continue
			}
			s.params = append(s.params, t)
		}
		// One window plus one borrow together is accepted (bpf-mlir accepts it; windows and borrows keep their own rules).
		if sig.Results().Len() != 1 {
			bad(fd.Name.Pos(), "subprogram %s must return exactly one integer or bool (a BPF subprogram returns one value; a function without a result is not turned into one returning 0)", fn.Name())
			continue
		}
		rt, ok := goType(sig.Results().At(0).Type())
		if !ok {
			bad(fd.Name.Pos(), "subprogram %s returns %s; integers and bool only", fn.Name(), sig.Results().At(0).Type())
			continue
		}
		s.result = rt
	}
}

// checkRecursion stops cycles in the eBPF-side call graph, with the cycle path (GB010).
func (a *analyzer) checkRecursion() {
	edges := map[string][]GraphEdge{}
	for _, e := range a.graph.Edges {
		if e.Kind == "call" {
			edges[e.From] = append(edges[e.From], e)
		}
	}
	state := map[string]int{} // 0 unvisited / 1 on the path / 2 done
	var stack []string
	reported := map[string]bool{}
	var visit func(f string)
	visit = func(f string) {
		state[f] = 1
		stack = append(stack, f)
		for _, e := range edges[f] {
			switch state[e.To] {
			case 0:
				visit(e.To)
			case 1:
				var cycle []string
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i] == e.To {
						cycle = append(append([]string(nil), stack[i:]...), e.To)
						break
					}
				}
				key := strings.Join(cycle, ">")
				if !reported[key] {
					reported[key] = true
					var pos token.Position
					fmt.Sscanf(strings.ReplaceAll(e.Pos, ":", " "), "%s %d %d", &pos.Filename, &pos.Line, &pos.Column)
					a.diags = append(a.diags, Diagnostic{Verdict: Rejected, Code: GB010Recursion, Pos: pos, Path: cycle,
						Msg: "recursion among eBPF-side functions is not allowed (BPF-to-BPF calls must not form a cycle)"})
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[f] = 2
	}
	for _, p := range a.programs {
		if state[p.Symbol] == 0 {
			visit(p.Symbol)
		}
	}
}

// reportNotPrograms stops functions that take a context but are not program-shaped with GB008. Functions reachable from a program are stopped as subprograms
// by GB013 (the subprogram context parameter rules), so they are not reported here (not twice).
func (a *analyzer) reportNotPrograms() {
	for _, fd := range a.notPrograms {
		obj, _ := a.info.Defs[fd.Name].(*types.Func)
		if obj != nil && a.isBPF(obj) {
			continue
		}
		a.report(Rejected, GB008ProgramShape, fd.Name.Pos(), nil,
			"%s takes a program context but is not a program: an xdp program is a top-level func(ctx *bpf.XDPContext) bpf.XDPAction, a tcx program func(ctx *bpf.TCIngressContext or *bpf.TCEgressContext) bpf.TCAction, a fentry program func(ctx *bpf.FentryContext) with no result (and //gobpf:fentry <function> above it), a lsm program func(ctx *bpf.LSMContext) bpf.LSMRet (and //gobpf:lsm <hook> above it), a perf_event program func(ctx *bpf.PerfEventContext) with no result, a fsession program func(ctx *bpf.FsessionContext) with no result (and //gobpf:fsession <function> above it), an iter program func(ctx *bpf.IterContext) with no result (and //gobpf:iter bpf_map_elem <map> above it)", fd.Name.Name)
	}
}

// GoDecodeType returns the type expression of the generated gobpf_T (a struct with opaque holes for a record with a lock / timer, GoType otherwise).
func (r *RecordABI) GoDecodeType() string {
	if r.DecodeType != "" {
		return r.DecodeType
	}
	return r.GoType()
}

// maxMapEntries is the limit on a map's MaxEntries (bpf-mlir v0.17.0's K9): map definition BTF encodes `__uint(max_entries, N)` as an int array
// int[N], so only N ≤ 1073741823, whose size 4 × N bytes fits in u32, is valid BTF (clang emits the same BTF, and all three kernels refuse it).
// A ring buffer's MaxEntries (bytes) has the same limit — being a power of two, 2^30 and above stops.
const maxMapEntries = 1073741823

// checkMapSizeLimit stops maps whose MaxEntries exceeds maxMapEntries with GB009 (at the declaration's Go position, before bpf-mlir's compile-time K9).
func (a *analyzer) checkMapSizeLimit() {
	for _, m := range a.maps {
		if m.MaxEntries <= maxMapEntries {
			continue
		}
		at := m.maxPos
		if !at.IsValid() && m.obj != nil {
			at = m.obj.Pos()
		}
		a.report(Rejected, GB009MapDeclShape, at, nil, "map %s: MaxEntries %d is over the limit %d — the map definition's BTF encodes max_entries as an int array int[MaxEntries], whose size (4 × MaxEntries bytes) must fit in 32 bits (bpf-mlir K9 — clang emits the same BTF and all three kernels reject it)", m.Symbol, m.MaxEntries, maxMapEntries)
	}
}
