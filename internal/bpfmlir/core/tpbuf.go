package core

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"
)

// CheckTracepointBuffer checks only that args[0] is signed i32*.
// BTF type identity does not establish writable_size, writability or attach success.
func CheckTracepointBuffer(spec *btf.Spec, name, pointee string) ([]string, error) {
	if spec == nil {
		return nil, fmt.Errorf("tracepoint %s: target BTF unavailable: %w", name, requirements.ErrUnknown)
	}
	if pointee != "i32" {
		return []string{fmt.Sprintf("tracepoint %s: argument 0 unsupported pointee %s (expected i32)", name, pointee)}, nil
	}
	var td *btf.Typedef
	if err := btfexact.TypeByName(spec, "btf_trace_"+name, &td); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return []string{fmt.Sprintf("tracepoint %s: argument 0 expected pointee i32; no btf_trace_%s in target BTF", name, name)}, nil
		}
		return nil, fmt.Errorf("tracepoint %s BTF lookup: %w", name, err)
	}
	diffs := checkTPBufferPrototype(td)
	for i := range diffs {
		diffs[i] = fmt.Sprintf("tracepoint %s: argument 0 expected pointee i32; %s", name, diffs[i])
	}
	return diffs, nil
}

// Check the base after 32 modifiers; avoid formatting malformed graphs recursively.
func stripTPBuffer(t btf.Type) (btf.Type, error) {
	seen := map[btf.Type]bool{}
	for depth := 0; ; depth++ {
		// cilium TypeID 0 is typed nil *Void, distinct from a nil pointer graph.
		if _, ok := t.(*btf.Void); ok {
			return t, nil
		}
		if t == nil || reflect.ValueOf(t).IsNil() {
			return nil, errors.New("nil BTF type")
		}
		if seen[t] {
			return nil, errors.New("BTF modifier cycle")
		}
		seen[t] = true
		var next btf.Type
		switch v := t.(type) {
		case *btf.Typedef:
			next = v.Type
		case *btf.Const:
			next = v.Type
		case *btf.Volatile:
			next = v.Type
		case *btf.Restrict:
			next = v.Type
		case *btf.TypeTag:
			next = v.Type
		default:
			return t, nil
		}
		if depth == 32 {
			return nil, errors.New("BTF modifier depth exceeds 32")
		}
		t = next
	}
}

func checkTPBufferPrototype(t btf.Type) []string {
	bad := func(message string) []string { return []string{message} }
	t, err := stripTPBuffer(t)
	if err != nil {
		return bad(err.Error())
	}
	p, ok := t.(*btf.Pointer)
	if !ok {
		return bad("target must be a function pointer")
	}
	t, err = stripTPBuffer(p.Target)
	if err != nil {
		return bad(err.Error())
	}
	f, ok := t.(*btf.FuncProto)
	if !ok {
		return bad("function pointer must target FUNC_PROTO")
	}
	if len(f.Params) < 2 {
		return bad("FUNC_PROTO data / argument 0 missing")
	}
	ret, err := stripTPBuffer(f.Return)
	if err != nil {
		return bad(err.Error())
	}
	if _, ok := ret.(*btf.Void); !ok {
		return bad("return must be void")
	}
	data, err := stripTPBuffer(f.Params[0].Type)
	if err != nil {
		return bad(err.Error())
	}
	dp, ok := data.(*btf.Pointer)
	if !ok {
		return bad("data must be void pointer")
	}
	data, err = stripTPBuffer(dp.Target)
	if err != nil {
		return bad(err.Error())
	}
	if _, ok := data.(*btf.Void); !ok {
		return bad("data must be void pointer")
	}
	arg, err := stripTPBuffer(f.Params[1].Type)
	if err != nil {
		return bad(err.Error())
	}
	ap, ok := arg.(*btf.Pointer)
	if !ok {
		return bad("argument 0 must be a pointer")
	}
	arg, err = stripTPBuffer(ap.Target)
	if err != nil {
		return bad(err.Error())
	}
	integer, ok := arg.(*btf.Int)
	if !ok {
		return bad(fmt.Sprintf("argument 0 expected pointee i32; got %T", arg))
	}
	if integer.Size != 4 || integer.Encoding != btf.Signed {
		return bad(fmt.Sprintf("argument 0 expected pointee i32; got INT %s size=%d encoding=%d", integer.Name, integer.Size, integer.Encoding))
	}
	return nil
}
