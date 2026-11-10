package core

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// CO-RE enum value relocations (ebpf.scx.const / ebpf.core.enum_value)
// resolved offline with cilium/ebpf's btf.CORERelocate, and the static
// placement of each relocated ld_imm64 relative to the CO-RE existence guards
// (core.type_exists / core.field_exists). Resolution does not look at
// reachability: an absent constant is poisoned wherever it is; whether the
// verifier sees the poison depends on the placement, which the codegen decides
// (the backend may sink or hoist the ld_imm64).

// EnumAccess is one enumval_value relocation of a program.
type EnumAccess struct {
	Insn     int    // Instruction index (ld_imm64 counts as one, following cilium/ebpf).
	Relo     string // cilium/ebpf relocation description.
	Local    int64  // The instruction's immediate before the fixup (the compiler's local value).
	Target   int64  // The immediate after the fixup (meaningless when Poisoned).
	Poisoned bool   // The target lacks the constant: the loader writes ld_imm64 r10, 0xbad2310.
}

// programInsns returns a copy of program prog's instructions (cilium appends
// the called subprograms) and its collection's BTF.
func programInsns(elfPath, prog string) (asm.Instructions, *btf.Spec, error) {
	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return nil, nil, err
	}
	ps := spec.Programs[prog]
	if ps == nil {
		return nil, nil, fmt.Errorf("%s: no program %q", elfPath, prog)
	}
	if spec.Types == nil {
		return nil, nil, fmt.Errorf("%s: no BTF", elfPath)
	}
	insns := make(asm.Instructions, len(ps.Instructions))
	copy(insns, ps.Instructions)
	return insns, spec.Types, nil
}

// RelocateEnumValues applies program prog's CO-RE relocations against target
// BTF and reports the enumval_value ones. Every relocation of the program is
// resolved together (as a loader does); only enum value ones are returned.
func RelocateEnumValues(elfPath, prog string, target *btf.Spec) ([]EnumAccess, error) {
	insns, types, err := programInsns(elfPath, prog)
	if err != nil {
		return nil, err
	}
	var relos []*btf.CORERelocation
	var at []int
	for i := range insns {
		if r := btf.CORERelocationMetadata(&insns[i]); r != nil {
			relos = append(relos, r)
			at = append(at, i)
		}
	}
	if len(relos) == 0 {
		return nil, nil
	}
	fixups, err := btf.CORERelocate(relos, []*btf.Spec{target}, binary.LittleEndian, types.TypeID)
	if err != nil {
		return nil, err
	}
	var out []EnumAccess
	for k, i := range at {
		if !strings.Contains(relos[k].String(), "enumval_value") {
			continue
		}
		before := insns[i]
		if !before.IsConstantLoad(asm.DWord) {
			return nil, fmt.Errorf("insn %d: enumval_value on %v, not ld_imm64", i, before)
		}
		if err := fixups[k].Apply(&insns[i]); err != nil {
			return nil, fmt.Errorf("insn %d: %w", i, err)
		}
		after := insns[i]
		a := EnumAccess{Insn: i, Relo: relos[k].String(), Local: before.Constant, Target: after.Constant}
		a.Poisoned = after.OpCode.IsDWordLoad() && after.Dst == asm.R10 && after.Constant == btf.COREBadRelocationSentinel
		out = append(out, a)
	}
	return out, nil
}

// EnumPlacement is where one enumval_value ld_imm64 sits relative to the
// program's CO-RE existence guards.
type EnumPlacement struct {
	Insn   int    // The ld_imm64's instruction index.
	Relo   string // Its relocation.
	Guards []int  // Instruction indices of the existence relocations whose true edge dominates it.
}

// guardEdge is an existence relocation (type_exists / field_exists) and the
// conditional jump on its register against 0.
type guardEdge struct {
	reloc, jump int
	trueSucc    int // The successor taken when the guard is 1.
}

// EnumGuardPlacement reports, for each enumval_value relocation of program
// prog, the existence guards whose true edge every path from the entry
// crosses (the ld_imm64 is unreachable when that edge is removed). The CFG
// follows jumps, fall-through and bpf-to-bpf calls (callee entry and return
// to the next instruction); a guard is the first conditional jump on the
// guard's destination register against the immediate 0 after it. ksym.exists
// guards (weak extern addresses, not CO-RE) are not recognized.
func EnumGuardPlacement(elfPath, prog string) ([]EnumPlacement, error) {
	insns, _, err := programInsns(elfPath, prog)
	if err != nil {
		return nil, err
	}
	// Raw slot offsets: jumps count ld_imm64 as two slots.
	raw := make([]int, len(insns))
	byRaw := map[int]int{}
	off := 0
	for i, ins := range insns {
		raw[i] = off
		byRaw[off] = i
		off += int(ins.Size() / asm.InstructionSize)
	}
	target := func(i int) (int, error) {
		t, ok := byRaw[raw[i]+1+int(insns[i].Offset)]
		if !ok {
			return 0, fmt.Errorf("insn %d: jump into the middle of an instruction", i)
		}
		return t, nil
	}
	// cilium leaves bpf-to-bpf calls unresolved (Constant -1 and a Reference
	// to the callee's symbol) until the program is linked, so a call is
	// resolved by symbol; a resolved call (Constant ≥ 0, no Reference) by its
	// offset. Anything else stops (a self-edge made the callee
	// unreachable and every guard was counted for it).
	bySym := map[string]int{}
	for i, ins := range insns {
		if s := ins.Symbol(); s != "" {
			bySym[s] = i
		}
	}
	callTarget := func(i int) (int, error) {
		if ref := insns[i].Reference(); ref != "" {
			t, ok := bySym[ref]
			if !ok {
				return 0, fmt.Errorf("insn %d: call to %q, which is not a function of the program", i, ref)
			}
			return t, nil
		}
		if insns[i].Constant < 0 {
			return 0, fmt.Errorf("insn %d: unresolved call (constant %d, no reference)", i, insns[i].Constant)
		}
		t, ok := byRaw[raw[i]+1+int(insns[i].Constant)]
		if !ok {
			return 0, fmt.Errorf("insn %d: call into the middle of an instruction", i)
		}
		return t, nil
	}
	succ := make([][]int, len(insns))
	for i, ins := range insns {
		op := ins.OpCode
		cls := op.Class()
		switch {
		case cls.IsJump() && op.JumpOp() == asm.Exit:
		case cls.IsJump() && op.JumpOp() == asm.Ja:
			t, err := target(i)
			if err != nil {
				return nil, err
			}
			succ[i] = []int{t}
		case ins.IsFunctionCall():
			t, err := callTarget(i)
			if err != nil {
				return nil, err
			}
			succ[i] = []int{t, i + 1}
		case ins.IsLoadOfFunctionPointer():
			// A callback (bpf_loop / for_each / timer / user_ringbuf) enters
			// through the helper that receives this address; the edge from the
			// address load stands for that later call (the helper follows it
			// on the same path in the compiler's lowering).
			t, err := callTarget(i)
			if err != nil {
				return nil, err
			}
			succ[i] = []int{i + 1, t}
		case cls.IsJump() && op.JumpOp() != asm.Call:
			t, err := target(i)
			if err != nil {
				return nil, err
			}
			succ[i] = []int{i + 1, t}
		default:
			if i+1 < len(insns) {
				succ[i] = []int{i + 1}
			}
		}
	}
	var guards []guardEdge
	var enums []EnumPlacement
	for i := range insns {
		r := btf.CORERelocationMetadata(&insns[i])
		if r == nil {
			continue
		}
		s := r.String()
		switch {
		case strings.Contains(s, "enumval_value"):
			enums = append(enums, EnumPlacement{Insn: i, Relo: s})
		case strings.Contains(s, "type_exists") || strings.Contains(s, "field_exists"):
			dst := insns[i].Dst
			for j := i + 1; j < len(insns); j++ {
				in := insns[j]
				if !in.OpCode.Class().IsJump() || in.OpCode.JumpOp() == asm.Call || in.OpCode.JumpOp() == asm.Exit || in.OpCode.JumpOp() == asm.Ja {
					if in.Dst == dst && !in.OpCode.Class().IsJump() {
						break // The register is overwritten before any test.
					}
					continue
				}
				if in.Dst != dst || in.OpCode.Source() != asm.ImmSource || in.Constant != 0 {
					continue
				}
				t, err := target(j)
				if err != nil {
					return nil, err
				}
				switch in.OpCode.JumpOp() {
				case asm.JEq:
					guards = append(guards, guardEdge{reloc: i, jump: j, trueSucc: j + 1})
				case asm.JNE:
					guards = append(guards, guardEdge{reloc: i, jump: j, trueSucc: t})
				}
				break
			}
		}
	}
	reach := func(cut guardEdge) []bool {
		seen := make([]bool, len(insns))
		stack := []int{0}
		seen[0] = true
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, m := range succ[n] {
				if n == cut.jump && m == cut.trueSucc {
					continue
				}
				if m < len(insns) && !seen[m] {
					seen[m] = true
					stack = append(stack, m)
				}
			}
		}
		return seen
	}
	// A read unreachable with no edge cut cannot be judged (a cut cannot make
	// it unreachable): stop rather than count every guard for it.
	base := reach(guardEdge{jump: -1})
	for _, e := range enums {
		if !base[e.Insn] {
			return nil, fmt.Errorf("insn %d (%s): unreachable from the entry with no guard edge removed — the CFG is incomplete", e.Insn, e.Relo)
		}
	}
	for _, g := range guards {
		seen := reach(g)
		for k := range enums {
			if !seen[enums[k].Insn] {
				enums[k].Guards = append(enums[k].Guards, g.reloc)
			}
		}
	}
	return enums, nil
}
