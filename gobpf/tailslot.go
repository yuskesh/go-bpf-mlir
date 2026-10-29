package gobpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// Tail call slots (the same order as bpf-mlir bindgen's LoadObjectsWithTailSlots):
// (1) the check bindrt.CheckTailSlots without touching the kernel (the ELF's tailslot rows == the generated TailSlots, every ELF program is in the generated Programs) —
// inside verifyEmbedded, in all of Load, LoadUnchecked and LoadCollectionSpec → (2) (Load only) Precheck → (3) load all programs and maps →
// (4) set **only the declared slots** in the prog_array (undeclared slots stay empty). If any step fails the collection is closed.
//
// The kernel removes prog_array entries when the last user-space reference to the map closes — do not close Objects while attached (the same caution as bpf-mlir's bindgen).

// TailSlotError is a mismatch between the generated file's tail call slot declarations and the embedded ELF's tailslot rows (it wraps bindrt.CheckTailSlots' error).
// It stops, before any kernel object is created, a build where only the TailSlot declarations changed after generation without rerunning go generate.
type TailSlotError struct {
	Err   error      // bindrt.CheckTailSlots' error
	Decls []TailSlot // the generated file's declarations (with Go positions)
}

func (e *TailSlotError) Error() string {
	var ds []string
	for _, d := range e.Decls {
		ds = append(ds, fmt.Sprintf("%s[%d] = %s at %s", d.Map, d.Slot, d.Program, d.Pos))
	}
	decl := "none"
	if len(ds) > 0 {
		decl = strings.Join(ds, "; ")
	}
	return fmt.Sprintf("gobpf: the tail-call slots of the generated binding do not match the embedded ELF (%s): %v (Go declaration: %s)", regenerateHint, e.Err, decl)
}

func (e *TailSlotError) Unwrap() error { return e.Err }

// checkTailSlots is check (1). It is skipped for an object with no slots in either the ELF or the generated file (no tail calls) — bindrt's "every ELF program is
// in the generated Programs" is a condition for loading the slot programs (bpf-mlir's bindgen also calls it only for bindings with slots),
// so the existing checks of an object without slots do not change.
func checkTailSlots(o *Object, p *bindrt.Parsed) error {
	if len(o.TailSlots) == 0 && len(p.Requirements().TailSlots) == 0 {
		return nil
	}
	want := make([]requirements.TailSlot, 0, len(o.TailSlots))
	for _, s := range o.TailSlots {
		want = append(want, requirements.TailSlot{Map: s.Map, Slot: s.Slot, Program: s.Program})
	}
	progs := make([]string, 0, len(o.Programs))
	for _, pr := range o.Programs {
		progs = append(progs, pr.Symbol)
	}
	if err := p.CheckTailSlots(want, progs); err != nil {
		return &TailSlotError{Err: err, Decls: o.TailSlots}
	}
	return nil
}

// updateTailSlot sets one slot (the package's tests inject failures here).
var updateTailSlot = func(m *ebpf.Map, slot uint32, p *ebpf.Program) error { return m.Update(slot, p, ebpf.UpdateAny) }

// setTailSlots is step (4) — it sets only the declared slots. On error the caller closes the collection.
func setTailSlots(o *Object, coll *ebpf.Collection) error {
	for _, s := range o.TailSlots {
		m, okM := coll.Maps[s.Map]
		p, okP := coll.Programs[s.Program]
		if !okM || !okP {
			return fmt.Errorf("gobpf: tail-call slot %s[%d] = %s (%s): the loaded collection has no map %q or program %q (%s)", s.Map, s.Slot, s.Program, s.Pos, s.Map, s.Program, regenerateHint)
		}
		if err := updateTailSlot(m, s.Slot, p); err != nil {
			return fmt.Errorf("gobpf: setting tail-call slot %s[%d] = %s (%s): %w", s.Map, s.Slot, s.Program, s.Pos, err)
		}
	}
	return nil
}
