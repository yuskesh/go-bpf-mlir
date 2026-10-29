package gobpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// ext (freplace) programs (directive `//gobpf:ext <program> <function>`):
//
//   - **The replacement target is only a program of the same object (the same ELF)**. Load has 2 stages: load the rest with the ext programs removed, then load the ext programs
//     with the target program of the same Load as AttachTarget (without attaching). There is no API taking another program's fd
//     (never replace another process's program — the reviewer's instruction).
//   - The requirements' freplace extret / extarg are checked through ExtTargets. The check is against **the BTF of the target program's function in the embedded ELF**
//     (the same declaration cilium looks up from the target program's BTF when loading the ext) — this assumes the target is in the same ELF,
//     and that assumption is bound by the generated binding's ExtTarget (a non-ext program of the same object). A non-ext program name, an ext without an ExtTarget,
//     an ExtTarget that is not a program of the same object, or a function not among the target program's functions is requirements.ErrUnknown
//     (ext_target_unknown — stops). **A target in another ELF is never passed silently with the ELF's own BTF**.
//   - AttachExt attaches with a link to the load-time target, then compares the link info's target_obj_id with the target program's id.
//
// A non-root loader needs CAP_BPF + CAP_PERFMON for the ext load, plus the capability of the target's kind (CAP_NET_ADMIN for xdp). **CAP_SYS_ADMIN is
// not needed**: the kernel's BPF_BTF_GET_FD_BY_ID needs CAP_SYS_ADMIN, but Program.Handle, which cilium's findTargetInProgram uses, returns the BTF of a program
// it loaded itself from a cache without that syscall (see the note on Handle / SetHandle in prog.go). gobpf targets only programs of the same Load,
// so only this path is used (measured: 7.1.8 passed with {bpf, net_admin, perfmon}, outside the prediction).

// extTargetOf returns the replacement target of an ext program (a non-ext program of the same object).
func extTargetOf(o *Object, program string) (ext, target *Program, err error) {
	for i := range o.Programs {
		if o.Programs[i].Symbol == program {
			ext = &o.Programs[i]
		}
	}
	if ext == nil || ext.Kind != "ext" {
		return nil, nil, fmt.Errorf("program %s is not an ext program of the embedded object", program)
	}
	if ext.ExtTarget == "" {
		return nil, nil, fmt.Errorf("ext program %s has no replacement target in the generated binding (regenerate with go generate)", program)
	}
	for i := range o.Programs {
		if o.Programs[i].Symbol == ext.ExtTarget && o.Programs[i].Kind != "ext" {
			target = &o.Programs[i]
		}
	}
	if target == nil {
		return nil, nil, fmt.Errorf("ext program %s: the replacement target %s is not a non-ext program of the embedded object (gobpf replaces only functions of its own object's programs)", program, ext.ExtTarget)
	}
	return ext, target, nil
}

// extCaps is the live caps plus the ext target check (requirements.ExtTargets — the target program's functions in the embedded ELF).
type extCaps struct {
	livecaps.LiveCaps
	o *Object
}

// withExtTargets adds ExtTargets to the check caps of an object with ext programs (live caps only — other caps (recorded caps, uprobe,
// the ksyscall declaration caps) stay unchanged, and their ext rows stop with ext_target_unknown).
func withExtTargets(o *Object, caps requirements.Capabilities) requirements.Capabilities {
	has := false
	for _, p := range o.Programs {
		has = has || p.Kind == "ext"
	}
	if !has {
		return caps
	}
	if c, ok := caps.(livecaps.LiveCaps); ok {
		return extCaps{LiveCaps: c, o: o}
	}
	return caps
}

// CheckExtTarget implements requirements.ExtTargets: it checks function fn of the target program of program (ext) against that program's
// function BTF in the embedded ELF (the declaration cilium looks up at load) — global linkage, argument count, return value, and integer argument types.
func (c extCaps) CheckExtTarget(program, fn string, nargs int, ret string, args []string) ([]string, error) {
	return checkExtTarget(c.o, program, fn, nargs, ret, args)
}

func checkExtTarget(o *Object, program, fn string, nargs int, ret string, args []string) ([]string, error) {
	ext, target, err := extTargetOf(o, program)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, requirements.ErrUnknown)
	}
	if ext.Attach != fn {
		return nil, fmt.Errorf("ext program %s replaces %s in the generated binding, but the requirements name %s: %w", program, ext.Attach, fn, requirements.ErrUnknown)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(o.ELF))
	if err != nil {
		return nil, fmt.Errorf("reading the embedded ELF (%v): %w", err, requirements.ErrUnknown)
	}
	ps := spec.Programs[target.Symbol]
	if ps == nil {
		return nil, fmt.Errorf("the embedded ELF has no program %s (the replacement target of %s): %w", target.Symbol, program, requirements.ErrUnknown)
	}
	var f *btf.Func
	for _, ins := range ps.Instructions {
		if m := btf.FuncMetadata(&ins); m != nil && m.Name == fn {
			f = m
		}
	}
	if f == nil {
		return nil, fmt.Errorf("function %s is not one of program %s's functions in the embedded ELF: %w", fn, target.Symbol, requirements.ErrUnknown)
	}
	var out []string
	if f.Linkage != btf.GlobalFunc {
		out = append(out, fmt.Sprintf("function %s has linkage %v in program %s, not global (ext replaces only global functions)", fn, f.Linkage, target.Symbol))
	}
	proto, ok := f.Type.(*btf.FuncProto)
	if !ok {
		return append(out, fmt.Sprintf("function %s has no FUNC_PROTO in program %s", fn, target.Symbol)), nil
	}
	if len(proto.Params) != nargs {
		out = append(out, fmt.Sprintf("function %s takes %d arguments in program %s, but the object declares %d", fn, len(proto.Params), target.Symbol, nargs))
	}
	if got := btfIntSpelling(proto.Return); got != ret {
		out = append(out, fmt.Sprintf("function %s returns %s in program %s, but the object declares %s", fn, got, target.Symbol, ret))
	}
	for i, want := range args {
		if want == "-" || i >= len(proto.Params) {
			continue
		}
		if got := btfIntSpelling(proto.Params[i].Type); got != want {
			out = append(out, fmt.Sprintf("argument %d of function %s is %s in program %s, but the object reads it as %s", i, fn, got, target.Symbol, want))
		}
	}
	return out, nil
}

// btfIntSpelling is the requirements' integer spelling (u32, i64 …, void, otherwise the type's name).
func btfIntSpelling(t btf.Type) string {
	if t == nil {
		return "void"
	}
	switch u := btf.UnderlyingType(t).(type) {
	case *btf.Void:
		return "void"
	case *btf.Int:
		if u.Encoding&btf.Signed != 0 {
			return fmt.Sprintf("i%d", u.Size*8)
		}
		return fmt.Sprintf("u%d", u.Size*8)
	default:
		return fmt.Sprintf("%T", u)
	}
}

// splitExt removes the ext programs from spec and returns a spec of only the removed programs (the maps keep the same declarations — the second-stage load replaces them with the first stage's maps).
// It returns nil when there are no ext programs. extTargetOf restricts each ext's target to a program of the same object.
func splitExt(o *Object, spec *ebpf.CollectionSpec) (*ebpf.CollectionSpec, error) {
	var exts []*Program
	for i := range o.Programs {
		if o.Programs[i].Kind == "ext" {
			exts = append(exts, &o.Programs[i])
		}
	}
	if len(exts) == 0 {
		return nil, nil
	}
	second := spec.Copy()
	keep := map[string]bool{}
	for _, e := range exts {
		if _, _, err := extTargetOf(o, e.Symbol); err != nil {
			return nil, fmt.Errorf("gobpf: %w", err)
		}
		if spec.Programs[e.Symbol] == nil {
			return nil, fmt.Errorf("gobpf: the embedded ELF has no program %q (regenerate with go generate)", e.Symbol)
		}
		keep[e.Symbol] = true
		delete(spec.Programs, e.Symbol)
	}
	for name := range second.Programs {
		if !keep[name] {
			delete(second.Programs, name)
		}
	}
	return second, nil
}

// loadExt is the second stage: it loads the ext programs with the target program from the first-stage collection as AttachTarget (without attaching) and adds them to coll.
// The maps are replaced with the first stage's maps (cilium's MapReplacements — they share the same maps).
func loadExt(o *Object, coll *ebpf.Collection, second *ebpf.CollectionSpec, opts ebpf.CollectionOptions) error {
	for name, ps := range second.Programs {
		_, target, err := extTargetOf(o, name)
		if err != nil {
			return fmt.Errorf("gobpf: %w", err)
		}
		tp := coll.Programs[target.Symbol]
		if tp == nil {
			return fmt.Errorf("gobpf: ext program %s: the replacement target %s was not loaded", name, target.Symbol)
		}
		ps.AttachTarget = tp
		ps.AttachTo = o.entryBySymbol(name).Attach
	}
	opts.MapReplacements = coll.Maps
	c2, err := ebpf.NewCollectionWithOptions(second, opts)
	if err != nil {
		return fmt.Errorf("gobpf: loading the ext programs against their replacement targets: %w", err)
	}
	defer c2.Close()
	for name := range second.Programs {
		coll.Programs[name] = c2.DetachProgram(name)
	}
	return nil
}

// entryBySymbol returns the object's program row.
func (o *Object) entryBySymbol(sym string) *Program {
	for i := range o.Programs {
		if o.Programs[i].Symbol == sym {
			return &o.Programs[i]
		}
	}
	return nil
}

// AttachExt attaches an ext program (a function value) with a link to its load-time target (a function of a program of the same Load — directive `//gobpf:ext <program> <function>`)
// (cilium's link.AttachFreplace(nil, "", prog)). After attaching it compares the link info's target_obj_id with the target
// program's id, closing the link with an error if they differ. **The function name is not compared after attaching** (the function is the id cilium looked up by name from the target program's
// BTF at load, and the kernel checks its type. Mapping target_btf_id back to a name with cilium's cached BTF is a later step — reading BTF
// was expected to need CAP_SYS_ADMIN, but the cached path turned out not to need it).
// Closing the link restores the original function. Only the target program's function is replaced (other programs calling the same function do not change).
func AttachExt(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "ext", "gobpf.AttachExt"); err != nil {
		return nil, err
	}
	tp := o.coll.Programs[e.ExtTarget]
	if tp == nil {
		return nil, fmt.Errorf("gobpf.AttachExt: program %s: the replacement target %s is not loaded", e.Symbol, e.ExtTarget)
	}
	tinfo, err := tp.Info()
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachExt: program %s: reading the replacement target %s: %w", e.Symbol, e.ExtTarget, err)
	}
	tid, ok := tinfo.ID()
	if !ok {
		return nil, fmt.Errorf("gobpf.AttachExt: program %s: the kernel does not report the id of the replacement target %s", e.Symbol, e.ExtTarget)
	}
	l, err := link.AttachFreplace(nil, "", p)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachExt: program %s replacing %s of %s: %w", e.Symbol, e.Attach, e.ExtTarget, err)
	}
	info, err := l.Info()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachExt: program %s: cannot confirm the replacement target: %w", e.Symbol, err)
	}
	tr := info.Tracing()
	if tr == nil || tr.TargetObjectId != uint32(tid) {
		got := "no tracing link info"
		if tr != nil {
			got = fmt.Sprintf("program id %d", tr.TargetObjectId)
		}
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachExt: program %s was attached to %s, not %s (program id %d); detached", e.Symbol, got, e.ExtTarget, tid)
	}
	return l, nil
}
