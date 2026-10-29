package requirements

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BpftoolProbe uses bpftool feature probe kernel -j output directly as recorded
// capabilities. It is input to pre-load/deploy compatibility checks, not compilation.
type BpftoolProbe struct {
	ProgramTypes map[string]bool     `json:"program_types"` // have_<name>_prog_type
	MapTypes     map[string]bool     `json:"map_types"`     // have_<name>_map_type
	Helpers      map[string][]string `json:"helpers"`       // <prog type>_available_helpers: [bpf_<name>...]
}

// ParseBpftoolProbe reads bpftool JSON, loudly rejecting missing sections.
func ParseBpftoolProbe(data []byte) (*BpftoolProbe, error) {
	var p BpftoolProbe
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.ProgramTypes == nil || p.MapTypes == nil || p.Helpers == nil {
		return nil, fmt.Errorf("not a `bpftool feature probe -j` output (program_types / map_types / helpers missing)")
	}
	return &p, nil
}

// An unrecorded item is an error, not false: unprobed does not mean absent.
func (p *BpftoolProbe) HasProgType(name string, _ int64) (bool, error) {
	v, ok := p.ProgramTypes["have_"+name+"_prog_type"]
	if !ok {
		return false, fmt.Errorf("the probe does not mention program type %q", name)
	}
	return v, nil
}

func (p *BpftoolProbe) HasMapType(name string, _ int64) (bool, error) {
	v, ok := p.MapTypes["have_"+name+"_map_type"]
	if !ok {
		return false, fmt.Errorf("the probe does not mention map type %q", name)
	}
	return v, nil
}

func (p *BpftoolProbe) HasHelper(progType string, _ int64, helper string, _ int64) (bool, error) {
	list, ok := p.Helpers[progType+"_available_helpers"]
	if !ok {
		return false, fmt.Errorf("the probe has no helper list for program type %q", progType)
	}
	for _, h := range list {
		if strings.TrimPrefix(h, "bpf_") == helper {
			return true, nil
		}
	}
	return false, nil
}
