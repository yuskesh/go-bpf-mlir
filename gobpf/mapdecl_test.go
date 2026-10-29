package gobpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

// The map declaration check is bindrt.CheckMapDecls (both directions). Tests tell results apart by the type (*MapDeclError) and the Problems'
// Map / Field, not by the error text. Since it checks both directions, the test object declares every map in the ELF (as the generated file does) — below are copies of the
// map declarations of difftest's ev / hash / percpu (the record types and Decode have the same shape as each package's generated file).

// wantMapDecl confirms that err is a *MapDeclError holding only a mismatch of field f of map m, and that it includes gobpf's fix text.
func wantMapDecl(t *testing.T, err error, m, f string) {
	t.Helper()
	var me *MapDeclError
	if !errors.As(err, &me) {
		t.Fatalf("want a *MapDeclError (map %s %s), got %T %v", m, f, err, err)
	}
	if len(me.Problems) != 1 || me.Problems[0].Map != m || me.Problems[0].Field != f {
		t.Fatalf("want exactly the problem map %s field %s, got %+v", m, f, me.Problems)
	}
	if !strings.Contains(err.Error(), regenerateHint) {
		t.Fatalf("the error lacks gobpf's hint %q: %v", regenerateHint, err)
	}
}

// --- ev (Ctl, Drops, Events, Res) ---

// --- hash (Ctl, Out, H, IH, RV, L) ---

// --- percpu (Ctl, PA, P12, PI, PH, PL, Status, Shared) ---

// One Load parses the embedded ELF's requirements once (the schema, the layout map declarations and the precheck share one *bindrt.Parsed).
// The v0.3.0 path parsed 3 times (bindrt.CheckSchema, requirements.FromELF, bindrt.Precheck).
func TestLoadParsesRequirementsOnce(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	mu.Lock()
	before := parseCalled
	mu.Unlock()
	_, _, err := Load(blocking) // reaches the precheck stage and stops with *TargetError (no root needed)
	if !errors.As(err, new(*TargetError)) {
		t.Fatalf("want *TargetError, got %T %v", err, err)
	}
	mu.Lock()
	n := parseCalled - before
	mu.Unlock()
	if n != 1 {
		t.Fatalf("Load parsed the requirements %d times, want 1", n)
	}
}

// An ELF whose requirements cannot be read gives *RequirementsError (bindrt's type) and stops before touching the kernel.
func TestUnreadableRequirementsRefused(t *testing.T) {
	reset(t)
	o := exampleObject(t)
	o.ELF = []byte("not an ELF")
	Register(o)
	_, _, err := Load(blocking)
	var re *RequirementsError
	if !errors.As(err, &re) {
		t.Fatalf("want a *RequirementsError, got %T %v", err, err)
	}
	if _, err := LoadCollectionSpec(); !errors.As(err, new(*RequirementsError)) {
		t.Fatalf("LoadCollectionSpec: want a *RequirementsError, got %T %v", err, err)
	}
	assertNotLoaded(t)
	t.Logf("refused: %v", err)
}

// gobpf's message wrapping a *MapDeclError names the Go declaration of the offending map (type and position — the generated file's Pos).
// The verdict and type do not change (still *MapDeclError and Field through errors.As).
func TestMapDeclErrorNamesGoDeclaration(t *testing.T) {
	narrow := bpf.Array[uint32, uint32]{MaxEntries: 2}
	reset(t)
	o := exampleObject(t)
	o.Maps = []Map{{Symbol: "Counts", Var: &narrow, Pos: "main.go:29:5"}}
	Register(o)
	_, err := LoadCollectionSpec()
	wantMapDecl(t, err, "Counts", "value")
	if want := "(Go declaration: var Counts bpf.Array[uint32,uint32] at main.go:29:5)"; !strings.Contains(err.Error(), want) {
		t.Fatalf("the error must name the Go declaration %q: %v", want, err)
	}
	t.Logf("refused: %v", err)
}
