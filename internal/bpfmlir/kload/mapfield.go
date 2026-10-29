//go:build linux

package kload

// Probe verifier map-field/program-type compatibility with three loads:
// (a) type T references a map with an integer replacing the special member
// at equal size/alignment; (b) the same program references the special-field
// map; (c) control XDP references map (b). False requires both maps created,
// (a)/(c) accepted and (b) rejected by the verifier with EINVAL plus log. True
// requires (a)/(b) accepted. Missing privileges/resources, map failures, control
// rejection, unsupported probe type or missing tracing target yield ErrUnknown.
// Record verifier prose but do not use version-dependent wording as evidence.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// MapFieldTracingTarget supplies a fixed fentry probe target, independent of
// the real attachment: policy is per program type. Missing target BTF is Unknown.
const MapFieldTracingTarget = "do_sys_poll"

var (
	mapFieldMu    sync.Mutex
	mapFieldCache = map[string]mapFieldResult{}
)

type mapFieldResult struct {
	allowed bool
	err     error
}

// MapFieldProbe records accept, reject:<errno>:<last verifier line>, or error:<...>.
type MapFieldProbe struct {
	Plain, Field, Control string
}

func (LiveCaps) AllowsMapField(progType string, progTypeID int64, field string) (bool, error) {
	key := fmt.Sprintf("%d/%s", progTypeID, field)
	mapFieldMu.Lock()
	defer mapFieldMu.Unlock()
	if r, ok := mapFieldCache[key]; ok {
		return r.allowed, r.err
	}
	allowed, _, err := ProbeMapField(progType, progTypeID, field)
	mapFieldCache[key] = mapFieldResult{allowed, err}
	return allowed, err
}

// probeOutcome is one load outcome.
type probeOutcome struct {
	accepted, verifierReject bool
	text                     string
}

// ProbeMapField runs three loads and returns the decision and observations.
func ProbeMapField(progType string, progTypeID int64, field string) (bool, MapFieldProbe, error) {
	var rec MapFieldProbe
	unknown := func(format string, a ...any) (bool, MapFieldProbe, error) {
		return false, rec, fmt.Errorf(format+": %w", append(a, requirements.ErrUnknown)...)
	}
	pt := ebpf.ProgramType(progTypeID)
	switch pt {
	case ebpf.XDP, ebpf.Kprobe, ebpf.Tracing:
	default:
		return unknown("no map-field probe for program type %s", progType)
	}
	fieldType, plainType, err := mapFieldTypes(field)
	if err != nil {
		return unknown("%v", err)
	}
	plainMap, err := newFieldMap("mf_plain", plainType)
	if err != nil {
		rec.Plain = "error:" + err.Error()
		return unknown("creating the map without %s failed (%v)", field, err)
	}
	defer plainMap.Close()
	fieldMap, err := newFieldMap("mf_field", fieldType)
	if err != nil {
		rec.Field = "error:" + err.Error()
		return unknown("creating the map with %s failed (%v)", field, err)
	}
	defer fieldMap.Close()

	a := loadMapFieldProbe(pt, plainMap)
	rec.Plain = a.text
	b := loadMapFieldProbe(pt, fieldMap)
	rec.Field = b.text
	c := loadMapFieldProbe(ebpf.XDP, fieldMap)
	rec.Control = c.text
	switch {
	case !a.accepted:
		return unknown("the %s probe without %s was not accepted (%s) — cannot attribute a rejection to the field", progType, field, a.text)
	case b.accepted:
		return true, rec, nil
	case !c.accepted:
		return unknown("the xdp control with %s was not accepted (%s)", field, c.text)
	case b.verifierReject:
		return false, rec, nil
	}
	return unknown("the %s probe with %s failed without a verifier rejection (%s)", progType, field, b.text)
}

// mapFieldTypes builds the special-field value and equal-size/alignment integer
// control, each with a trailing u32 a. Use the UAPI bpf_spin_lock and bpf_timer
// BTF shapes.
func mapFieldTypes(field string) (btf.Type, btf.Type, error) {
	u32 := &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}
	u64 := &btf.Int{Name: "u64", Size: 8, Encoding: btf.Unsigned}
	var ft, stand btf.Type
	var size uint32
	switch field {
	case "bpf_spin_lock":
		ft = &btf.Struct{Name: "bpf_spin_lock", Size: 4, Members: []btf.Member{{Name: "val", Type: u32}}}
		stand, size = u32, 4
	case "bpf_timer":
		arr := &btf.Array{Index: u32, Type: u64, Nelems: 2}
		ft = &btf.Struct{Name: "bpf_timer", Size: 16, Members: []btf.Member{{Name: "__opaque", Type: arr}}}
		stand, size = &btf.Array{Index: u32, Type: u64, Nelems: 2}, 16
	default:
		return nil, nil, fmt.Errorf("no probe for map field %s", field)
	}
	mk := func(t btf.Type) btf.Type {
		// Both values round size+4 up to the same alignment (eight or four).
		total := (size + 4 + 7) &^ 7
		if size == 4 {
			total = 8
		}
		return &btf.Struct{Name: "mf_val", Size: total, Members: []btf.Member{
			{Name: "f", Type: t, Offset: 0},
			{Name: "a", Type: u32, Offset: btf.Bits(size * 8)},
		}}
	}
	return mk(ft), mk(stand), nil
}

func newFieldMap(name string, value btf.Type) (*ebpf.Map, error) {
	sz, err := btf.Sizeof(value)
	if err != nil {
		return nil, err
	}
	return ebpf.NewMap(&ebpf.MapSpec{
		Name: name, Type: ebpf.Array, KeySize: 4, ValueSize: uint32(sz), MaxEntries: 1,
		Key: &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}, Value: value,
	})
}

// loadMapFieldProbe loads type pt with map ld_imm64, r0=0 and exit.
func loadMapFieldProbe(pt ebpf.ProgramType, m *ebpf.Map) probeOutcome {
	spec := &ebpf.ProgramSpec{
		Name: "mapfield_probe", Type: pt, License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}
	if pt == ebpf.Tracing {
		spec.AttachType = ebpf.AttachTraceFEntry
		spec.AttachTo = MapFieldTracingTarget
	}
	prog, err := ebpf.NewProgram(spec)
	if err == nil {
		prog.Close()
		return probeOutcome{accepted: true, text: "accept"}
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && errors.Is(err, unix.EINVAL) {
		last := ""
		for i := len(ve.Log) - 1; i >= 0; i-- {
			// processed/verification-time statistics are not reasons; use the prior line.
			if l := strings.TrimSpace(ve.Log[i]); l != "" && !strings.HasPrefix(l, "processed ") && !strings.HasPrefix(l, "verification time") {
				last = l
				break
			}
		}
		return probeOutcome{verifierReject: true, text: "reject:EINVAL:" + last}
	}
	return probeOutcome{text: "error:" + strings.SplitN(err.Error(), "\n", 2)[0]}
}
