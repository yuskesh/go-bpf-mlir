package bindgen

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CheckSchemaMapsInELF checks map declarations before generating bindings.
// ELF .maps symbols (the names cilium assigns into Objects) and requirement map
// rows must be the same set. Every core.maps symbol must exist in the ELF, or
// binding load would inevitably fail with missing map; report all missing names.
//
// Extra ELF maps are allowed: compiler-generated USDT spec maps are absent from
// canonical schema. This differs from CheckMapDecls' default bidirectional check;
// bindgen does not generate maps.json. Only declared core.maps are checked, even
// when coverage.maps is omitted.
func CheckSchemaMapsInELF(schemaJSON []byte, elfMaps, reqMaps []string) error {
	var s schema
	if err := json.Unmarshal(schemaJSON, &s); err != nil {
		return fmt.Errorf("cannot read schema: %w", err)
	}
	inELF := map[string]bool{}
	for _, m := range elfMaps {
		inELF[m] = true
	}
	inReq := map[string]bool{}
	for _, m := range reqMaps {
		inReq[m] = true
	}
	var onlyELF, onlyReq []string
	for m := range inELF {
		if !inReq[m] {
			onlyELF = append(onlyELF, m)
		}
	}
	for m := range inReq {
		if !inELF[m] {
			onlyReq = append(onlyReq, m)
		}
	}
	if len(onlyELF) > 0 || len(onlyReq) > 0 {
		sort.Strings(onlyELF)
		sort.Strings(onlyReq)
		return fmt.Errorf("ELF .maps symbols differ from .ebpf_requirements map rows (.maps only: [%s], requirements only: [%s]) — compiler declarations differ from the actual ELF",
			strings.Join(onlyELF, " "), strings.Join(onlyReq, " "))
	}
	var missing []string
	for _, m := range s.Core.Maps {
		if !inELF[m.Symbol] {
			missing = append(missing, m.Symbol)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("schema maps [%s] are absent from the ELF — the generated bindings Objects assigns these maps, so load always fails with `missing map`. "+
			"Fix: build the ELF from .mlir that references these maps (bindgen requires an ELF referencing every schema map), or split the schema to match the ELF maps",
			strings.Join(missing, " "))
	}
	return nil
}
