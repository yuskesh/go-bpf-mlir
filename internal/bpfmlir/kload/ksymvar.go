//go:build linux

package kload

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/core"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"
)

// the queries ksym_vars / btf_presence (target BTF files — vmlinux and
// every module under /sys/kernel/btf) and kconfig (the kernel config file
// libbpf and cilium read). BTF-file and config-file queries only: no program
// load, so the answers do not depend on the privilege.

// percpuSection is the DATASEC of per-CPU variables in vmlinux / module BTF
// (pahole; the verifier's __check_pseudo_btf_id marks a VAR in it MEM_PERCPU).
const percpuSection = ".data..percpu"

var moduleBTFDir = "/sys/kernel/btf"

type btfSources struct {
	vm     *btf.Spec
	vmErr  error
	mods   map[string]*btf.Spec // module name → split spec (only its own types)
	modErr error                // the module set could not be read completely
}

var (
	sourcesOnce sync.Once
	sources     btfSources
)

func liveSources() *btfSources {
	sourcesOnce.Do(func() {
		sources.vm, sources.vmErr = vmlinux()
		if sources.vmErr == nil {
			sources.mods, sources.modErr = loadModuleBTF(moduleBTFDir, sources.vm)
		}
	})
	return &sources
}

// loadModuleBTF reads every module BTF of dir (all entries but vmlinux). Any
// unreadable entry makes the set incomplete: absence is then not established.
func loadModuleBTF(dir string, base *btf.Spec) (map[string]*btf.Spec, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("module BTF set %s: %w", dir, err)
	}
	mods := map[string]*btf.Spec{}
	for _, e := range ents {
		if e.Name() == "vmlinux" {
			continue
		}
		s, err := btf.LoadSplitSpec(filepath.Join(dir, e.Name()), base)
		if err != nil {
			return nil, fmt.Errorf("module BTF %s: %w", e.Name(), err)
		}
		mods[e.Name()] = s
	}
	return mods, nil
}

// KsymVar answers ksym_vars: "<percpu|plain> <slot>" for the single VAR name in
// vmlinux, ErrKsymAbsent when neither vmlinux nor any module BTF has it, and
// Unknown when the module set is incomplete, the VAR is only in a module (the
// verifier then needs the module's BTF fd — not established here), or vmlinux
// has two VARs of the name.
func (LiveCaps) KsymVar(name string) (string, error) {
	s := liveSources()
	return ksymVarIn(s.vm, s.vmErr, s.mods, s.modErr, name)
}

// TypePresent answers btf_presence type/<S>: the struct S in vmlinux.
func (LiveCaps) TypePresent(name string) (bool, error) {
	s := liveSources()
	return typePresentIn(s.vm, s.vmErr, s.mods, s.modErr, name)
}

// FieldPresent answers btf_presence field/<S>.<path>: the member path in the
// vmlinux struct S (anonymous members found as CheckKFields does).
func (LiveCaps) FieldPresent(name, path string) (bool, error) {
	s := liveSources()
	return fieldPresentIn(s.vm, s.vmErr, s.mods, s.modErr, name, path)
}

func btfUnknown(what string, err error) error {
	return fmt.Errorf("%s: target BTF unavailable: %w: %w", what, err, requirements.ErrUnknown)
}

func typesOf[T btf.Type](spec *btf.Spec, name string) ([]T, error) {
	ts, err := btfexact.Types(spec, name)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, t := range ts {
		if v, ok := t.(T); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// inModules names the modules whose own types have a T named name (sorted).
func inModules[T btf.Type](mods map[string]*btf.Spec, name string) ([]string, error) {
	var out []string
	for m, s := range mods {
		ts, err := typesOf[T](s, name)
		if err != nil {
			return nil, fmt.Errorf("module BTF %s: %w", m, err)
		}
		if len(ts) > 0 {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

// absentOrUnknown decides a name vmlinux lacks: Unknown if the module set is
// incomplete or a module has it, else absent (the caller's sentinel).
func absentOrUnknown[T btf.Type](what string, mods map[string]*btf.Spec, modErr error, name string, absent error) error {
	if modErr != nil {
		return fmt.Errorf("%s: vmlinux has none and %v: %w", what, modErr, requirements.ErrUnknown)
	}
	in, err := inModules[T](mods, name)
	if err != nil {
		return fmt.Errorf("%s: %v: %w", what, err, requirements.ErrUnknown)
	}
	if len(in) > 0 {
		return fmt.Errorf("%s: only in module BTF %s: %w", what, strings.Join(in, ","), requirements.ErrUnknown)
	}
	return fmt.Errorf("%s: neither vmlinux nor the %d module BTFs have it: %w", what, len(mods), absent)
}

func ksymVarIn(vm *btf.Spec, vmErr error, mods map[string]*btf.Spec, modErr error, name string) (string, error) {
	what := "VAR " + name
	if vmErr != nil {
		return "", btfUnknown(what, vmErr)
	}
	vs, err := typesOf[*btf.Var](vm, name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	switch len(vs) {
	case 0:
		return "", absentOrUnknown[*btf.Var](what, mods, modErr, name, requirements.ErrKsymAbsent)
	case 1:
	default:
		return "", fmt.Errorf("%s: vmlinux has %d VARs of the name: %w", what, len(vs), requirements.ErrUnknown)
	}
	class := "plain"
	pc, err := percpuVars(vm)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if pc[vs[0]] {
		class = requirements.KsymPercpu
	}
	return class + " " + slotOf(vs[0].Type), nil
}

var percpuCache sync.Map // *btf.Spec → map[*btf.Var]bool

// percpuVars is the set of VARs listed in the per-CPU DATASEC of spec.
func percpuVars(spec *btf.Spec) (map[*btf.Var]bool, error) {
	if v, ok := percpuCache.Load(spec); ok {
		return v.(map[*btf.Var]bool), nil
	}
	set := map[*btf.Var]bool{}
	for t, err := range spec.All() {
		if err != nil {
			return nil, fmt.Errorf("reading the target BTF: %w", err)
		}
		ds, ok := t.(*btf.Datasec)
		if !ok || ds.Name != percpuSection {
			continue
		}
		for _, vs := range ds.Vars {
			if v, ok := vs.Type.(*btf.Var); ok {
				set[v] = true
			}
		}
	}
	v, _ := percpuCache.LoadOrStore(spec, set)
	return v.(map[*btf.Var]bool), nil
}

// slotOf spells the VAR's type as a ksymvar slot after typedef, const /
// volatile / restrict and type tags (__rcu): an INT is i / u and its width, a
// pointer to a named STRUCT is ptr:<S>; anything else is other:<…> (never a
// row's slot, so it is a mismatch).
func slotOf(t btf.Type) string {
	switch u := btf.UnderlyingType(t).(type) {
	case *btf.Int:
		if u.Encoding&btf.Signed != 0 {
			return fmt.Sprintf("i%d", u.Size*8)
		}
		return fmt.Sprintf("u%d", u.Size*8)
	case *btf.Pointer:
		tgt := btf.UnderlyingType(u.Target)
		if st, ok := tgt.(*btf.Struct); ok && st.Name != "" {
			return "ptr:" + st.Name
		}
		return "other:pointer-to-" + kindOf(tgt)
	default:
		return "other:" + kindOf(u)
	}
}

func kindOf(t btf.Type) string {
	return strings.ToLower(strings.TrimPrefix(fmt.Sprintf("%T", t), "*btf."))
}

func vmStruct(vm *btf.Spec, vmErr error, mods map[string]*btf.Spec, modErr error, name string) (*btf.Struct, error) {
	what := "struct " + name
	if vmErr != nil {
		return nil, btfUnknown(what, vmErr)
	}
	ss, err := typesOf[*btf.Struct](vm, name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	switch len(ss) {
	case 0:
		return nil, absentOrUnknown[*btf.Struct](what, mods, modErr, name, errTypeAbsent)
	case 1:
		return ss[0], nil
	}
	return nil, fmt.Errorf("%s: vmlinux has %d structs of the name: %w", what, len(ss), requirements.ErrUnknown)
}

var errTypeAbsent = errors.New("type absent")

func typePresentIn(vm *btf.Spec, vmErr error, mods map[string]*btf.Spec, modErr error, name string) (bool, error) {
	_, err := vmStruct(vm, vmErr, mods, modErr, name)
	if errors.Is(err, errTypeAbsent) {
		return false, nil
	}
	return err == nil, err
}

func fieldPresentIn(vm *btf.Spec, vmErr error, mods map[string]*btf.Spec, modErr error, name, path string) (bool, error) {
	st, err := vmStruct(vm, vmErr, mods, modErr, name)
	if errors.Is(err, errTypeAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return core.HasField(st, path), nil
}

// KconfigValue answers kconfig: the raw value of the first CONFIG_<x>= line of
// /boot/config-<release>, else /proc/config.gz (the order of libbpf 1.7
// bpf_object__read_kconfig_file and cilium internal/linux/kconfig.go).
// ErrKconfigAbsent when no line sets it (`# CONFIG_X is not set` is not read);
// Unknown when neither file is readable or the file is malformed (libbpf then
// fails the load — no value is guessed).
func (LiveCaps) KconfigValue(name string) (string, error) {
	kconfigOnce.Do(func() { kconfigVals, kconfigErr = readKconfig() })
	return kconfigValueFrom(kconfigVals, kconfigErr, name)
}

var (
	kconfigOnce sync.Once
	kconfigVals map[string]string
	kconfigErr  error
	// kconfigPaths is read in order; the first that opens is the file.
	kconfigPaths = func() []string {
		rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
		if err != nil {
			return []string{"/proc/config.gz"}
		}
		return []string{"/boot/config-" + strings.TrimSpace(string(rel)), "/proc/config.gz"}
	}
)

func readKconfig() (map[string]string, error) {
	var tried []string
	for _, p := range kconfigPaths() {
		f, err := os.Open(p)
		if err != nil {
			tried = append(tried, err.Error())
			continue
		}
		defer f.Close()
		var r io.Reader = f
		if strings.HasSuffix(p, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return nil, fmt.Errorf("kernel config %s: %v: %w", p, err, requirements.ErrUnknown)
			}
			defer gz.Close()
			r = gz
		}
		vals, err := parseKconfig(r)
		if err != nil {
			return nil, fmt.Errorf("kernel config %s: %v: %w", p, err, requirements.ErrUnknown)
		}
		return vals, nil
	}
	return nil, fmt.Errorf("no kernel config file (%s): %w", strings.Join(tried, "; "), requirements.ErrUnknown)
}

// parseKconfig mirrors libbpf 1.7 bpf_object__process_kconfig_line: lines not
// starting with CONFIG_ are skipped; a CONFIG_ line without '=' or with an
// empty value is an error (the whole file); the first occurrence wins.
func parseKconfig(r io.Reader) (map[string]string, error) {
	vals := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		l := sc.Text()
		if !strings.HasPrefix(l, "CONFIG_") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, fmt.Errorf("line %d %q: no '=' separator", n, l)
		}
		if v == "" {
			return nil, fmt.Errorf("line %d %q: no value", n, l)
		}
		if _, set := vals[k]; !set {
			vals[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return vals, nil
}

func kconfigValueFrom(vals map[string]string, err error, name string) (string, error) {
	if err != nil {
		return "", err
	}
	v, ok := vals[name]
	if !ok {
		return "", fmt.Errorf("the kernel config has no %s= line: %w", name, requirements.ErrKconfigAbsent)
	}
	return v, nil
}
