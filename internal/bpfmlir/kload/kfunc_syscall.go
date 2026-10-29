//go:build linux

package kload

// Privilege-independent metadata queries: kfunc_protos from vmlinux FUNC_PROTO
// and syscall_args from syscalls/sys_enter_<name>/format or __do_sys_<name> BTF.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/btf"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// KfuncSpelling unwraps typedef/const/volatile/type_tag and emits section 3
// i8..u64/bool, ptr:<struct>/ptr:void/ptr:<integer>, or void return spellings.
// Unrepresentable types use ?<kind>, matching no valid row spelling.
func KfuncSpelling(t btf.Type, ret bool) string {
	if t == nil {
		if ret {
			return "void"
		}
		return "?void"
	}
	switch u := btf.UnderlyingType(t).(type) {
	case *btf.Void:
		return "void"
	case *btf.Int:
		return intSpelling(u)
	case *btf.Enum:
		if u.Signed {
			return fmt.Sprintf("i%d", u.Size*8)
		}
		return fmt.Sprintf("u%d", u.Size*8)
	case *btf.Pointer:
		switch p := btf.UnderlyingType(u.Target).(type) {
		case *btf.Void:
			return "ptr:void"
		case *btf.Int:
			return "ptr:" + intSpelling(p)
		case *btf.Struct:
			return "ptr:" + p.Name
		case *btf.Union:
			return "ptr:" + p.Name
		default:
			return fmt.Sprintf("ptr:?%T", p)
		}
	default:
		return fmt.Sprintf("?%T", u)
	}
}

func intSpelling(i *btf.Int) string {
	if i.Encoding&btf.Bool != 0 {
		return "bool"
	}
	if i.Encoding&btf.Signed != 0 || i.Encoding&btf.Char != 0 {
		return fmt.Sprintf("i%d", i.Size*8)
	}
	return fmt.Sprintf("u%d", i.Size*8)
}

// CompareKfuncProto returns return/argument mismatches, or empty on agreement.
func CompareKfuncProto(name string, proto *btf.FuncProto, ret string, args []string) []string {
	var out []string
	if got := KfuncSpelling(proto.Return, true); got != ret {
		out = append(out, fmt.Sprintf("kfunc %s returns %s in the target BTF, but the object declares %s", name, got, ret))
	}
	if len(proto.Params) != len(args) {
		got := make([]string, len(proto.Params))
		for i, p := range proto.Params {
			got[i] = KfuncSpelling(p.Type, false)
		}
		return append(out, fmt.Sprintf("kfunc %s takes %d arguments (%s) in the target BTF, but the object passes %d (%s)", name, len(proto.Params), strings.Join(got, ", "), len(args), strings.Join(args, ", ")))
	}
	for i, p := range proto.Params {
		if got := KfuncSpelling(p.Type, false); got != args[i] {
			out = append(out, fmt.Sprintf("argument %d (%s) of kfunc %s is %s in the target BTF, but the object passes %s", i, requirements.ArgName(p.Name), name, got, args[i]))
		}
	}
	return out
}

// CheckKfunc checks vmlinux FUNC name/FUNC_PROTO. Missing names yield kfunc_sig;
// unreadable BTF is Unknown. Do not require bpf_kfunc DECL_TAG: the verifier
// loudly rejects functions that are not registered for use.
func (LiveCaps) CheckKfunc(name, ret string, args []string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %v: %w", err, requirements.ErrUnknown)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return []string{fmt.Sprintf("kfunc %s is not found in the target BTF (vmlinux)", name)}, nil
		}
		return nil, fmt.Errorf("kfunc %s: %v: %w", name, err, requirements.ErrUnknown)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return []string{fmt.Sprintf("kfunc %s has no FUNC_PROTO in the target BTF", name)}, nil
	}
	return CompareKfuncProto(name, proto, ret, args), nil
}

// SyscallFormatArg retains one sys_enter argument's declaration and name.
type SyscallFormatArg struct {
	Type, Name string
}

// ParseSyscallEnterFormat returns argument declarations in order, excluding
// common_* and __syscall_nr. Use declaration text, not field size/signed:
// syscall_enter_define_fields writes sizeof(unsigned long) and zero for all.
func ParseSyscallEnterFormat(text string) ([]SyscallFormatArg, error) {
	var out []SyscallFormatArg
	seenNr := false
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "field:") {
			continue
		}
		decl, _, _ := strings.Cut(strings.TrimPrefix(l, "field:"), ";")
		decl = strings.TrimSpace(decl)
		i := strings.LastIndexAny(decl, " *")
		if i < 0 || i == len(decl)-1 {
			return nil, fmt.Errorf("syscall format: cannot read %q", l)
		}
		typ, name := strings.TrimSpace(decl[:i+1]), decl[i+1:]
		if name == "__syscall_nr" {
			seenNr = true
			continue
		}
		if strings.HasPrefix(name, "common_") {
			continue
		}
		if !seenNr {
			return nil, fmt.Errorf("syscall format: field %q before __syscall_nr", name)
		}
		out = append(out, SyscallFormatArg{typ, name})
	}
	if !seenNr {
		return nil, fmt.Errorf("syscall format: no __syscall_nr field")
	}
	return out, nil
}

// cIntNames maps source C integer spellings to vmlinux BTF INT names.
var cIntNames = map[string]string{
	"unsigned": "unsigned int", "signed": "int", "unsigned long": "long unsigned int", "long": "long int", "signed long": "long int",
	"unsigned short": "short unsigned int", "short": "short int", "long long": "long long int", "unsigned long long": "long long unsigned int",
	"signed char": "signed char",
}

// SyscallTypeSpelling emits i8..u64/ptr. Any '*' means ptr; otherwise unwrap
// qualifiers and resolve BTF INT/typedef/enum names. Failure returns ok=false.
func SyscallTypeSpelling(spec *btf.Spec, typ string) (string, bool) {
	if strings.Contains(typ, "*") {
		return "ptr", true
	}
	var words []string
	for _, w := range strings.Fields(typ) {
		if w != "const" && w != "volatile" && w != "__user" {
			words = append(words, w)
		}
	}
	name := strings.Join(words, " ")
	if n, ok := cIntNames[name]; ok {
		name = n
	}
	if strings.HasPrefix(name, "enum ") {
		var e *btf.Enum
		if spec.TypeByName(strings.TrimPrefix(name, "enum "), &e) == nil {
			return KfuncSpelling(e, false), true
		}
		return "", false
	}
	types, err := spec.AnyTypesByName(name)
	if err != nil {
		return "", false
	}
	for _, t := range types {
		switch t.(type) {
		case *btf.Int, *btf.Typedef:
			s := KfuncSpelling(t, false)
			if s == "bool" {
				s = "u8"
			}
			if !strings.HasPrefix(s, "?") && !strings.HasPrefix(s, "ptr:") {
				return s, true
			}
			if strings.HasPrefix(s, "ptr:") {
				return "ptr", true
			}
		}
	}
	return "", false
}

// syscallBTFCharPointerDepth retains pointee identity instead of reducing every pointer to ptr.
// A known non-char type has depth -1; an unresolved type remains Unknown.
func syscallBTFCharPointerDepth(t btf.Type) (depth int, known bool) {
	for i := 0; i < 32; i++ {
		if t == nil {
			return 0, false
		}
		switch u := btf.UnderlyingType(t).(type) {
		case *btf.Pointer:
			depth++
			t = u.Target
		case *btf.Int:
			if u.Name == "char" && u.Size == 1 {
				return depth, true
			}
			return -1, true
		case *btf.Void, *btf.Struct, *btf.Union, *btf.Enum, *btf.Array, *btf.FuncProto:
			return -1, true
		default:
			return 0, false
		}
	}
	return 0, false
}

func syscallCharPointerDepth(spec *btf.Spec, typ string) (int, bool) {
	var words []string
	for _, w := range strings.Fields(strings.ReplaceAll(typ, "*", " * ")) {
		if w != "__user" {
			words = append(words, w)
		}
	}
	typ = strings.Join(words, " ")
	if d, known := tpCharPointerDepth(TPFormatField{Declaration: typ + " argument"}); known {
		return d, true
	}
	if spec == nil {
		return 0, false
	}
	var base []string
	for _, w := range strings.Fields(strings.ReplaceAll(typ, "*", " ")) {
		if w != "const" && w != "volatile" && w != "restrict" {
			base = append(base, w)
		}
	}
	types, err := spec.AnyTypesByName(strings.Join(base, " "))
	if err != nil {
		return 0, false
	}
	for _, t := range types {
		if d, known := syscallBTFCharPointerDepth(t); known {
			if d < 0 {
				return d, true
			}
			return d + strings.Count(typ, "*"), true
		}
	}
	return 0, false
}

// compareSysarg compares argument n spelling with its sysarg declaration.
func compareSysarg(syscall string, n int, typ string, args []string, names []string, from string) []string {
	if n > len(args) {
		return []string{fmt.Sprintf("syscall %s takes %d arguments in the target's %s, but the object reads argument %d", syscall, len(args), from, n)}
	}
	if args[n-1] != typ {
		return []string{fmt.Sprintf("argument %d (%s) of syscall %s is %s in the target's %s, but the object reads it as %s", n, names[n-1], syscall, args[n-1], from, typ)}
	}
	return nil
}

// CheckSyscallArg prefers readable tracefs declaration text; unreadable
// tracefs is Unknown. For a missing event, use __do_sys_<name> FUNC_PROTO;
// missing both sources is Unknown.
func (LiveCaps) CheckSyscallArg(name string, n int, typ string) ([]string, error) {
	if !requirementsCName(name) {
		return nil, unknownf("syscall %q is not a C identifier", name)
	}
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %v: %w", err, requirements.ErrUnknown)
	}
	var errs []string
	for _, root := range tracefsRoots {
		b, err := os.ReadFile(filepath.Join(root, "events", "syscalls", "sys_enter_"+name, "format"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err.Error())
				continue
			}
			return nil, unknownf("the tracefs format of syscalls/sys_enter_%s is not readable (%v) — tracefs needs root (a non-root loader uses caps recorded as root with a live re-probe — ebpf-precheck --caps --live)", name, err)
		}
		fields, err := ParseSyscallEnterFormat(string(b))
		if err != nil {
			return nil, unknownf("syscalls/sys_enter_%s: %v", name, err)
		}
		args, names := make([]string, len(fields)), make([]string, len(fields))
		for i, f := range fields {
			if (typ == "strptr" || typ == "strarray") && i == n-1 {
				d, known := syscallCharPointerDepth(spec, f.Type)
				if !known {
					return nil, unknownf("argument %d (%s) of syscall %s has unresolved string pointer type %q", n, f.Name, name, f.Type)
				}
				args[i], names[i] = "not-"+typ, f.Name
				wantDepth := 1
				if typ == "strarray" {
					wantDepth = 2
				}
				if d == wantDepth {
					args[i] = typ
				}
				continue
			}
			s, ok := SyscallTypeSpelling(spec, f.Type)
			if !ok {
				if i == n-1 {
					return nil, unknownf("argument %d (%s) of syscall %s has the type %q in the tracefs format, which the target BTF does not resolve to an integer", n, f.Name, name, f.Type)
				}
				s = "?" + f.Type
			}
			args[i], names[i] = s, f.Name
		}
		return compareSysarg(name, n, typ, args, names, "tracefs format"), nil
	}
	var fn *btf.Func
	if err := spec.TypeByName("__do_sys_"+name, &fn); err == nil {
		if proto, ok := fn.Type.(*btf.FuncProto); ok {
			args, names := make([]string, len(proto.Params)), make([]string, len(proto.Params))
			for i, p := range proto.Params {
				if (typ == "strptr" || typ == "strarray") && i == n-1 {
					d, known := syscallBTFCharPointerDepth(p.Type)
					if !known {
						return nil, unknownf("argument %d of syscall %s has unresolved BTF string pointer type", n, name)
					}
					args[i], names[i] = "not-"+typ, requirements.ArgName(p.Name)
					wantDepth := 1
					if typ == "strarray" {
						wantDepth = 2
					}
					if d == wantDepth {
						args[i] = typ
					}
					continue
				}
				s := KfuncSpelling(p.Type, false)
				switch {
				case strings.HasPrefix(s, "ptr:"):
					s = "ptr"
				case s == "bool":
					s = "u8"
				}
				args[i], names[i] = s, requirements.ArgName(p.Name)
			}
			return compareSysarg(name, n, typ, args, names, "BTF __do_sys_"+name), nil
		}
	}
	return nil, unknownf("syscall %s has neither a tracefs format syscalls/sys_enter_%s (%s) nor a BTF FUNC __do_sys_%s", name, name, strings.Join(errs, "; "), name)
}

func requirementsCName(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
