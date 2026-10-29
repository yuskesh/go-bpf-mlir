package bindrt

// Load contracts accept ELF bytes and values extracted by caller-owned loader
// glue, without depending on cilium types. contract_test.go fixes error text.
// Wrappers own check ordering, including missing objects versus nil caps; these
// functions check values only after the wrapper has obtained them.

import (
	"bytes"
	"fmt"

	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// RequirementsError wraps an unreadable requirements section. Prefix is caller
// supplied; errors.As can recover a requirements.ParseError from Err.
type RequirementsError struct {
	Prefix string
	Err    error
}

func (e *RequirementsError) Error() string { return e.Prefix + ": " + e.Err.Error() }
func (e *RequirementsError) Unwrap() error { return e.Err }

// SchemaMismatchError reports different schema hashes for ELF and bindings.
type SchemaMismatchError struct {
	ELF, Want, Hint string
}

func (e *SchemaMismatchError) Error() string {
	return fmt.Sprintf("ELF was built from schema %q, bindings from schema %q — %s", e.ELF, e.Want, e.Hint)
}

// Parsed retains requirements so subsequent checks do not parse the ELF again.
type Parsed struct {
	req *requirements.Requirements
	elf []byte // ELF bytes for BTF record checks; nil after ParseRequirements.
}

// Parse reads ELF requirements, including derived map-field usage. It returns
// a RequirementsError on failure.
func Parse(elf []byte) (*Parsed, error) {
	req, err := requirements.FromELF(bytes.NewReader(elf))
	if err != nil {
		return nil, &RequirementsError{Prefix: "cannot read requirements from the embedded ELF", Err: err}
	}
	return &Parsed{req: req, elf: elf}, nil
}

// ParseRequirements reads section text without deriving map-field usage
// (MapFields is not_derived; docs/requirements_format.md section 7).
// Failures are wrapped in RequirementsError.
func ParseRequirements(section []byte) (*Parsed, error) {
	req, err := requirements.Parse(section)
	if err != nil {
		return nil, &RequirementsError{Prefix: "cannot read requirements", Err: err}
	}
	return &Parsed{req: req}, nil
}

// Requirements returns the parsed requirements; callers must not mutate them.
func (p *Parsed) Requirements() *requirements.Requirements { return p.req }

// CheckSchema rejects stale ELF/bindings pairs whose schema hashes differ.
// A mismatch is a SchemaMismatchError. The caller supplies a tool-specific repair
// hint; bindrt does not prescribe a frontend or regeneration command.
func (p *Parsed) CheckSchema(want, hint string) error {
	if p.req.SchemaSHA256 != want {
		return &SchemaMismatchError{ELF: p.req.SchemaSHA256, Want: want, Hint: hint}
	}
	return nil
}

// CheckTarget returns all unmet requirements without loading kernel objects.
// Nil caps is an error, never a request to skip checking.
func (p *Parsed) CheckTarget(caps requirements.Capabilities) ([]requirements.Unmet, error) {
	if caps == nil {
		return nil, fmt.Errorf("CheckTarget: no capabilities given (the check is not skipped)")
	}
	return requirements.Check(p.req, caps)
}

// Precheck returns TargetError for blocking unmet requirements, otherwise the
// remaining Unknown results. Check failures become PrecheckError. In either
// error case the caller must not load the embedded program.
func (p *Parsed) Precheck(caps requirements.Capabilities) ([]requirements.Unmet, error) {
	return classify(p.CheckTarget(caps))
}

// CheckTailSlots requires an exact tailslot declaration match and a binding for
// every ELF program, so none of the programs would be omitted from loading.
func (p *Parsed) CheckTailSlots(want []requirements.TailSlot, programs []string) error {
	req := p.req
	if len(req.TailSlots) != len(want) {
		return fmt.Errorf("ELF declares %d tail-call slots, the bindings %d", len(req.TailSlots), len(want))
	}
	for i := range want {
		if req.TailSlots[i] != want[i] {
			return fmt.Errorf("ELF tail-call slot %+v does not match the bindings (%+v)", req.TailSlots[i], want[i])
		}
	}
	known := map[string]bool{}
	for _, name := range programs {
		known[name] = true
	}
	for _, pr := range req.Programs {
		if !known[pr.Symbol] {
			return fmt.Errorf("ELF program %q is not in the bindings — it would not be loaded", pr.Symbol)
		}
	}
	return nil
}

// CheckSchema parses the ELF then calls Parsed.CheckSchema. Parse failures are
// RequirementsError. These byte-based wrappers parse once per call.
func CheckSchema(elf []byte, want, hint string) error {
	p, err := parseWith(elf, "cannot read ELF requirements")
	if err != nil {
		return err
	}
	return p.CheckSchema(want, hint)
}

// CheckTarget parses then calls Parsed.CheckTarget, rejecting nil caps first.
func CheckTarget(elf []byte, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	if caps == nil {
		return nil, fmt.Errorf("CheckTarget: no capabilities given (the check is not skipped)")
	}
	p, err := Parse(elf)
	if err != nil {
		return nil, err
	}
	return p.CheckTarget(caps)
}

// Precheck classifies CheckTarget results as Parsed.Precheck does.
func Precheck(elf []byte, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	return classify(CheckTarget(elf, caps))
}

// classify separates blocking mismatches from nonblocking results and errors.
func classify(unmet []requirements.Unmet, err error) ([]requirements.Unmet, error) {
	if err != nil {
		return nil, &PrecheckError{Err: err}
	}
	var blocking, rest []requirements.Unmet
	for _, u := range unmet {
		if u.BlocksLoad() {
			blocking = append(blocking, u)
		} else {
			rest = append(rest, u)
		}
	}
	if len(blocking) > 0 {
		return nil, &TargetError{Unmet: blocking}
	}
	return rest, nil
}

// CheckTailSlots parses then calls Parsed.CheckTailSlots.
func CheckTailSlots(elf []byte, want []requirements.TailSlot, programs []string) error {
	p, err := parseWith(elf, "cannot read ELF requirements")
	if err != nil {
		return err
	}
	return p.CheckTailSlots(want, programs)
}

func parseWith(elf []byte, prefix string) (*Parsed, error) {
	p, err := Parse(elf)
	if err != nil {
		err.(*RequirementsError).Prefix = prefix
		return nil, err
	}
	return p, nil
}

// Variable contains SectionName, Size and Offset extracted by the loader.
type Variable struct {
	Section      string
	Size, Offset uint32
}

// CheckVariable independently checks loader section, size and offset against
// the schema and ELF symbol. A nil v means no loader VariableSpec was found.
func CheckVariable(elf []byte, g layout.Global, v *Variable) error {
	if v == nil {
		return fmt.Errorf("global %s: loader VariableSpec is missing", g.Name)
	}
	off, err := layout.GlobalOffset(elf, g.Name)
	if err != nil {
		return err
	}
	if v.Section != g.Section || v.Size != g.Size || uint64(v.Offset) != off {
		return fmt.Errorf("global %s: loader reads %s at offset %d as %d bytes (schema: %s, %d bytes; ELF symbol offset: %d)", g.Name, v.Section, v.Offset, v.Size, g.Section, g.Size, off)
	}
	return nil
}
