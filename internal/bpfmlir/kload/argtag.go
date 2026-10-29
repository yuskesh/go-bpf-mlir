//go:build linux

package kload

// Probe arg:nonnull interpretation separately from DECL_TAG kind acceptance.
// An XDP main passes an initialized eight-byte stack pointer to global f,
// which dereferences u64*p without a check. The untagged control must reject
// mem_or_null, otherwise the probe cannot distinguish semantics and is Unknown.
// A tagged acceptance means supported; the same rejection means unsupported;
// every other outcome is Unknown. Refuse to decide when cilium would replace
// declaration tags through KernelMarshalOptions.ReplaceDeclTags.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

const memOrNull = "invalid mem access 'mem_or_null'"

var (
	argTagMu    sync.Mutex
	argTagCache = map[string]argTagResult{}
)

type argTagResult struct {
	has bool
	err error
}

// ArgTagProbe retains one probe's observations for developer reporting.
type ArgTagProbe struct {
	Tagged, Untagged string // accept or the relevant verifier rejection line.
}

func (LiveCaps) HasArgTagSemantics(progType string, progTypeID int64, tag, class string) (bool, error) {
	key := fmt.Sprintf("%d/%s/%s", progTypeID, tag, class)
	argTagMu.Lock()
	defer argTagMu.Unlock()
	if r, ok := argTagCache[key]; ok {
		return r.has, r.err
	}
	has, _, err := ProbeArgTag(progType, progTypeID, tag, class)
	argTagCache[key] = argTagResult{has, err}
	return has, err
}

// ProbeArgTag runs the load pair and returns the decision and observations.
func ProbeArgTag(progType string, progTypeID int64, tag, class string) (bool, ArgTagProbe, error) {
	var rec ArgTagProbe
	if ebpf.ProgramType(progTypeID) != ebpf.XDP {
		return false, rec, fmt.Errorf("no argument-tag probe for program type %s: %w", progType, requirements.ErrUnknown)
	}
	if tag != "arg:nonnull" || class != "mem" {
		return false, rec, fmt.Errorf("no probe for %s on %s pointers: %w", tag, class, requirements.ErrUnknown)
	}
	if btf.KernelMarshalOptions().ReplaceDeclTags {
		return false, rec, fmt.Errorf("the loader would replace decl tags on this target: %w", requirements.ErrUnknown)
	}
	untagged, uerr := loadArgTagProbe(nil)
	rec.Untagged = untagged
	if uerr != nil {
		return false, rec, uerr
	}
	if !strings.Contains(untagged, memOrNull) {
		return false, rec, fmt.Errorf("the untagged control was not rejected as %q (%s) — the probe cannot tell: %w", memOrNull, untagged, requirements.ErrUnknown)
	}
	tagged, terr := loadArgTagProbe([][]string{{tag}})
	rec.Tagged = tagged
	if terr != nil {
		return false, rec, terr
	}
	switch {
	case tagged == "accept":
		return true, rec, nil
	case strings.Contains(tagged, memOrNull):
		return false, rec, nil
	}
	return false, rec, fmt.Errorf("the tagged probe was rejected for another reason (%s): %w", tagged, requirements.ErrUnknown)
}

// loadArgTagProbe returns accept or the verifier rejection line. Failures
// before verifier checking, including permissions or BTF loading, are Unknown errors.
func loadArgTagProbe(paramTags [][]string) (string, error) {
	u64 := &btf.Int{Name: "u64", Size: 8, Encoding: btf.Unsigned}
	i32 := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	mainFn := &btf.Func{Name: "argtag_probe", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: i32, Params: []btf.FuncParam{{Name: "ctx", Type: &btf.Pointer{Target: &btf.Void{}}}}}}
	f := &btf.Func{Name: "f", Linkage: btf.GlobalFunc, Type: &btf.FuncProto{
		Return: i32, Params: []btf.FuncParam{{Name: "p", Type: &btf.Pointer{Target: u64}}}}, ParamTags: paramTags}
	insns := asm.Instructions{
		btf.WithFuncMetadata(asm.Mov.Imm(asm.R2, 0), mainFn),
		asm.StoreMem(asm.R10, -8, asm.R2, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R10),
		asm.Add.Imm(asm.R1, -8),
		asm.Call.Label("f"),
		asm.Mov.Imm(asm.R0, 2), // XDP_PASS
		asm.Return(),
		btf.WithFuncMetadata(asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord).WithSymbol("f"), f),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "argtag_probe", Type: ebpf.XDP, License: "GPL", Instructions: insns,
	})
	if err == nil {
		prog.Close()
		return "accept", nil
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return "", fmt.Errorf("argument-tag probe did not reach the verifier: %v: %w", err, requirements.ErrUnknown)
	}
	for _, l := range ve.Log {
		if strings.Contains(l, "invalid") || strings.Contains(l, "arg#") || strings.Contains(l, "tag") {
			return strings.TrimSpace(l), nil
		}
	}
	return strings.TrimSpace(strings.Join(ve.Log, " | ")), nil
}
