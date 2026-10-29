package requirements

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Typed companion rows check target-dependent layout and signature contracts
// that generic attach rows cannot express. See docs/requirements_format.md
// sections 3 and 4.
//
// validTypedAttachTarget validates the target spelling for these typed attach families.
func validTypedAttachTarget(attachType, target string) bool {
	switch attachType {
	case "trace_lsm", "freplace", "trace_struct_ops":
		return validCName(target)
	case "trace_tp":
		cat, ev, ok := strings.Cut(target, "/")
		return ok && validCName(cat) && validCName(ev)
	case "trace_perf":
		return target == "perf"
	}
	return false
}

// validIntOrDash accepts an integer spelling or '-' for an unread argument.
func validIntOrDash(s string) bool { return s == "-" || validIntSpelling(s) }

// parseTypedAttachCompanion parses tpfield/extret/extarg/structop rows in order:
// trace_tp -> tpfield (strictly increasing offsets); freplace -> one extret ->
// extarg (contiguous indices from zero); trace_struct_ops -> one structop ->
// retsig -> farg.
func (r *Requirements) parseTypedAttachCompanion(n int, f []string, line string) error {
	k := len(r.Attaches) - 1
	want := map[string]string{"tpfield": "trace_tp", "extret": "freplace", "extarg": "freplace", "structop": "trace_struct_ops"}[f[0]]
	if k < 0 || r.Attaches[k].Program != f[1] || r.Attaches[k].AttachType != want {
		return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
	}
	a := &r.Attaches[k]
	switch f[0] {
	case "tpfield":
		array := validKFieldByteArray(f[5])
		if array && r.Version < 17 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: tpfield type %s needs version 17", Section, n, f[5])
		}
		if f[5] == "strarray" && r.Version < 16 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: tpfield type strarray needs version 16", Section, n)
		}
		if f[5] == "strptr" && r.Version < 16 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: tpfield type strptr needs version 16", Section, n)
		}
		off, err1 := strconv.Atoi(f[3])
		b, err2 := strconv.Atoi(f[4])
		validType := (b == 1 || b == 2 || b == 4 || b == 8) && (f[5] == "i" || f[5] == "u" || ((f[5] == "strptr" || f[5] == "strarray") && b == 8))
		if array {
			validType = f[5] == fmt.Sprintf("[%d]u8", b) || f[5] == fmt.Sprintf("[%d]i8", b)
		}
		if err1 != nil || err2 != nil || off < 0 || !validType || !validCName(f[2]) {
			return perr(n, f[0], RuleValue, "%s line %d: bad tpfield row %q", Section, n, line)
		}
		if l := len(a.TPFields); l > 0 && off <= a.TPFields[l-1].Offset {
			return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
		}
		a.TPFields = append(a.TPFields, TPField{f[2], off, b, f[5]})
	case "extret":
		if a.ExtNargs >= 0 {
			return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
		}
		na, err := strconv.Atoi(f[2])
		if err != nil || na < 0 || !(validIntSpelling(f[3]) || f[3] == "void") {
			return perr(n, f[0], RuleValue, "%s line %d: bad extret row %q", Section, n, line)
		}
		a.ExtNargs, a.ExtRet = na, f[3]
	case "extarg":
		if a.ExtNargs < 0 {
			return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
		}
		idx, err := strconv.Atoi(f[2])
		if err != nil || !validIntOrDash(f[3]) {
			return perr(n, f[0], RuleValue, "%s line %d: bad extarg row %q", Section, n, line)
		}
		if idx != len(a.ExtArgs) {
			return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
		}
		if idx >= a.ExtNargs {
			return perr(n, f[0], RuleValue, "%s line %d: extarg index %d is not below the extret argument count %d %q", Section, n, idx, a.ExtNargs, line)
		}
		a.ExtArgs = append(a.ExtArgs, f[3])
	case "structop":
		if a.StructOpStruct != "" {
			return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
		}
		if !validCName(f[2]) || !validCName(f[3]) {
			return perr(n, f[0], RuleValue, "%s line %d: bad structop row %q", Section, n, line)
		}
		a.StructOpStruct, a.StructOpMember = f[2], f[3]
	}
	return nil
}

// TracepointFieldCaps checks tracefs events/<cat>/<event>/format fields.
// Missing capabilities or unreadable formats produce blocking tpfield_unknown.
// Non-root loaders combine recorded root caps with live re-probes using
// ebpf-precheck --caps --live; see docs/nonroot.md.
type TracepointFieldCaps interface {
	// CheckTracepointField checks event <cat>/<event>, byte offset, size and
	// sign (i/u). Mismatches return a message; unreadable/missing events wrap
	// ErrUnknown.
	CheckTracepointField(event, field string, offset, bytes int, sign string) ([]string, error)
}

// StructOpsMemberCaps checks target BTF struct_ops function-pointer members.
// Missing capabilities, BTF or a vmlinux struct (including module-only types)
// produce blocking structop_unknown.
type StructOpsMemberCaps interface {
	// CheckStructOpsMember requires bpf_struct_ops_<strct> and a function-pointer
	// member with matching FUNC_PROTO. nargs < 0 skips count, ret empty skips
	// return type; other returns are void/i8..u64. Args use struct/integer/'-'
	// spellings per index. Mismatches return a message.
	CheckStructOpsMember(strct, member string, nargs int, ret string, args []string) ([]string, error)
}

// ExtTargets supplies caller-owned freplace targets per program, like
// UprobeBinaries. Recorder stores Unknown rather than the target itself.
// Missing capabilities, target, BTF or function produce blocking ext_target_unknown.
type ExtTargets interface {
	// CheckExtTarget requires a global BTF FUNC fn whose count, void/integer return
	// and integer/'-' argument spellings match. Mismatches return a message.
	CheckExtTarget(program, fn string, nargs int, ret string, args []string) ([]string, error)
}

// genericOfTypedAttach preserves generic attach_type/attach_target checks after moving
// to typed attach rows. freplace had no generic attach row and returns false.
func genericOfTypedAttach(a Attach) (Attach, bool) {
	g := Attach{Program: a.Program, Generic: true, RetNargs: -1, ExtNargs: -1}
	switch a.AttachType {
	case "trace_lsm":
		g.AttachType, g.TargetKind, g.TargetValue = "lsm_mac", "lsm", a.Target
	case "trace_tp":
		g.AttachType, g.TargetKind, g.TargetValue = "tracepoint", "tp", a.Target
	case "trace_perf":
		g.AttachType, g.TargetKind = "perf_event", "perf"
	case "trace_struct_ops":
		g.AttachType, g.TargetKind, g.TargetValue = "struct_ops", "map", a.Target
	default:
		return Attach{}, false
	}
	g.Target = g.TargetKind
	if g.TargetValue != "" {
		g.Target += ":" + g.TargetValue
	}
	return g, true
}

// checkTypedAttach checks typed attach families. Keep Unmet Kind as string literals:
// spec_test checks the source against its table.
func checkTypedAttach(req *Requirements, a Attach, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	var out []Unmet
	if g, ok := genericOfTypedAttach(a); ok {
		u, err := checkGenericAttach(req, g, caps, asked)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	var u []Unmet
	var err error
	switch a.AttachType {
	case "trace_lsm":
		u, err = checkLSMArgs(a, caps)
	case "trace_tp":
		u, err = checkTPFields(a, caps)
	case "trace_perf":
		if a.Arch == "" {
			return nil, fmt.Errorf("program %s: trace_perf attach row without an arch row", a.Program)
		}
		u, _, err = checkArchAndCtx(a, caps) // Parse disallows ctxfield rows here; check architecture only.
	case "freplace":
		u, err = checkExt(a, caps)
	case "trace_struct_ops":
		u, err = checkStructOps(a, caps)
	}
	if err != nil {
		return nil, err
	}
	return append(out, u...), nil
}

// checkLSMArgs checks trace_lsm farg rows: structs via func_args on
// bpf_lsm_<hook> FUNC_PROTO, integers via func_param.
func checkLSMArgs(a Attach, caps Capabilities) ([]Unmet, error) {
	fn := "bpf_lsm_" + a.Target
	var out []Unmet
	structs := make([]string, len(a.FArgs))
	anyStruct := false
	for i, t := range a.FArgs {
		structs[i] = "-"
		if !validIntOrDash(t) {
			structs[i], anyStruct = t, true
		}
	}
	if anyStruct {
		fa, ok := capsAs[KernelFuncArgs](caps, QueryFuncArgs)
		if !ok {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: fn})
		} else {
			diffs, err := fa.CheckFuncArgs(fn, structs)
			if err != nil {
				if !errors.Is(err, ErrUnknown) {
					return nil, err
				}
				out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: fn, Detail: err.Error()})
			}
			for _, d := range diffs {
				out = append(out, Unmet{Kind: "farg", Program: a.Program, Name: fn, Detail: fmt.Sprintf("program %s: %s", a.Program, d)})
			}
		}
	}
	for i, t := range a.FArgs {
		if !validIntSpelling(t) {
			continue
		}
		name := fmt.Sprintf("%d of %s (%s)", i+1, fn, t)
		fp, ok := capsAs[KernelFuncParams](caps, QueryFuncParam)
		if !ok {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: "no BTF probe"})
			continue
		}
		diffs, err := fp.CheckFuncParam(fn, i+1, t)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "farg", Program: a.Program, Name: name, Detail: fmt.Sprintf("program %s: %s", a.Program, d)})
		}
	}
	return out, nil
}

// TPFieldName is the tpfield Unmet Name spelling fixed by corpus wants.
func TPFieldName(event string, t TPField) string {
	return fmt.Sprintf("%s.%s (offset %d, %d bytes, %s)", event, t.Field, t.Offset, t.Bytes, t.Sign)
}

// SyscallsCtxProblem rejects fields outside the BPF syscall context layout.
// Unlike tracefs records, syscall_trace_enter has nr@8 and args[6]@16+8k;
// syscall_trace_exit has nr@8 and ret@16. A tracefs __data_loc field such as
// sys_enter_write.__buf_val@40 would read BPF args[3], silently the wrong value.
// Schema.cpp applies the same rule. An empty string means no layout problem.
func SyscallsCtxProblem(event string, t TPField) string {
	cat, name, _ := strings.Cut(event, "/")
	if cat != "syscalls" {
		return ""
	}
	if validKFieldByteArray(t.Sign) {
		return fmt.Sprintf("field %s: inline array fields are not part of the BPF context of syscalls events", t.Field)
	}
	switch {
	case t.Offset == 8 && t.Bytes == 4:
		return ""
	case strings.HasPrefix(name, "sys_enter_") && t.Offset >= 16 && t.Offset < 64 && (t.Offset-16)%8 == 0 && t.Bytes == 8:
		return ""
	case strings.HasPrefix(name, "sys_exit_") && t.Offset == 16 && t.Bytes == 8:
		return ""
	}
	return fmt.Sprintf("field %s (offset %d, %d bytes) is not part of the BPF context of syscalls events "+
		"(struct syscall_trace_enter: nr at 8 (4 bytes), args[6] at 16 + 8k (8 bytes); struct syscall_trace_exit: nr at 8, ret at 16 (8 bytes)) "+
		"— the tracefs format of a syscalls event is not what a BPF program reads", t.Field, t.Offset, t.Bytes)
}

// checkTPFields queries tracepoint_fields for each trace_tp tpfield row.
func checkTPFields(a Attach, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	tc, ok := capsAs[TracepointFieldCaps](caps, QueryTracepointFields)
	for _, t := range a.TPFields {
		name := TPFieldName(a.Target, t)
		if p := SyscallsCtxProblem(a.Target, t); p != "" { // Reject invalid syscall context offsets without querying tracefs caps:
		// even a matching tracefs format would authorize the wrong BPF read.
			out = append(out, Unmet{Kind: "tpfield", Program: a.Program, Name: name, Detail: p})
			continue
		}
		if !ok {
			out = append(out, Unmet{Kind: "tpfield_unknown", Program: a.Program, Name: name, Detail: "no tracepoint format probe (a non-root loader uses caps recorded as root with a live re-probe — ebpf-precheck --caps --live)"})
			continue
		}
		diffs, err := tc.CheckTracepointField(a.Target, t.Field, t.Offset, t.Bytes, t.Sign)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "tpfield_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "tpfield", Program: a.Program, Name: name, Detail: d})
		}
	}
	return out, nil
}

// checkExt checks freplace extret/extarg rows.
func checkExt(a Attach, caps Capabilities) ([]Unmet, error) {
	if a.ExtNargs < 0 {
		return nil, fmt.Errorf("program %s: freplace attach row without an extret row", a.Program)
	}
	et, ok := capsAs[ExtTargets](caps, QueryExtTargets)
	if !ok {
		return append([]Unmet(nil), Unmet{Kind: "ext_target_unknown", Program: a.Program, Name: a.Target, Detail: "no replacement target given (the target program is a loader input — a recorded caps does not carry it)"}), nil
	}
	diffs, err := et.CheckExtTarget(a.Program, a.Target, a.ExtNargs, a.ExtRet, a.ExtArgs)
	if errors.Is(err, ErrUnknown) {
		return append([]Unmet(nil), Unmet{Kind: "ext_target_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()}), nil
	}
	if err != nil {
		return nil, err
	}
	var out []Unmet
	for _, d := range diffs {
		out = append(out, Unmet{Kind: "ext_target", Program: a.Program, Name: a.Target, Detail: d})
	}
	return out, nil
}

// checkStructOps checks trace_struct_ops structop/retsig/farg rows.
func checkStructOps(a Attach, caps Capabilities) ([]Unmet, error) {
	if a.StructOpStruct == "" {
		return nil, fmt.Errorf("program %s: trace_struct_ops attach row without a structop row", a.Program)
	}
	name := a.StructOpStruct + "." + a.StructOpMember
	sc, ok := capsAs[StructOpsMemberCaps](caps, QueryStructOpsMembers)
	if !ok {
		return append([]Unmet(nil), Unmet{Kind: "structop_unknown", Program: a.Program, Name: name, Detail: "no struct_ops probe"}), nil
	}
	diffs, err := sc.CheckStructOpsMember(a.StructOpStruct, a.StructOpMember, a.RetNargs, a.RetType, a.FArgs)
	if errors.Is(err, ErrUnknown) {
		return append([]Unmet(nil), Unmet{Kind: "structop_unknown", Program: a.Program, Name: name, Detail: err.Error()}), nil
	}
	if err != nil {
		return nil, err
	}
	var out []Unmet
	for _, d := range diffs {
		out = append(out, Unmet{Kind: "structop", Program: a.Program, Name: name, Detail: d})
	}
	return out, nil
}

// StructOpsKey encodes <struct>.<member>/<nargs>/<ret>(<args>). Without retsig,
// nargs is -1 and ret is '-'.
func StructOpsKey(strct, member string, nargs int, ret string, args []string) string {
	if ret == "" {
		ret = "-"
	}
	return strct + "." + member + "/" + strconv.Itoa(nargs) + "/" + ret + "(" + strings.Join(args, ",") + ")"
}

// ExtTargetKey encodes <program>/<function>/<nargs>/<ret>(<args>).
func ExtTargetKey(program, fn string, nargs int, ret string, args []string) string {
	return program + "/" + fn + "/" + strconv.Itoa(nargs) + "/" + ret + "(" + strings.Join(args, ",") + ")"
}

// TPFieldKey encodes <cat>/<event>/<field>/<offset>/<bytes>/<i|u>.
func TPFieldKey(event, field string, offset, bytes int, sign string) string {
	return event + "/" + field + "/" + strconv.Itoa(offset) + "/" + strconv.Itoa(bytes) + "/" + sign
}
