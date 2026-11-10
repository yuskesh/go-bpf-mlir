package requirements

import (
	"errors"
	"fmt"
	"sort"
)

const NetkitMinVersion = 30

// NetkitCaps tests link creation independently for each direction. A program
// load alone does not establish that CONFIG_NETKIT supplies the link hook.
type NetkitCaps interface {
	HasNetkit(direction string) (bool, error)
}

func validNetkitDirection(d string) bool { return d == "primary" || d == "peer" }

func checkNetkit(a Attach, caps Capabilities) ([]Unmet, error) {
	unknown := func(detail string) ([]Unmet, error) {
		u := Unmet{Kind: "attach_netkit_unknown", Program: a.Program, Name: a.Target, Detail: detail}
		return []Unmet{u}, nil
	}
	n, ok := capsAs[NetkitCaps](caps, QueryNetkit)
	if !ok {
		return unknown("no netkit probe")
	}
	have, err := n.HasNetkit(a.Target)
	if errors.Is(err, ErrUnknown) {
		return unknown(err.Error())
	}
	if err != nil {
		return nil, err
	}
	if !have {
		return []Unmet{{Kind: "attach", Program: a.Program, Name: a.Target, Detail: "the target kernel has no netkit " + a.Target + " link"}}, nil
	}
	return nil, nil
}

func (c *RecordedCaps) HasNetkit(direction string) (bool, error) {
	if !validNetkitDirection(direction) {
		return false, fmt.Errorf("netkit: unknown direction %q", direction)
	}
	if r, err, use := c.privileged(QueryNetkit); !use {
		if err != nil {
			return false, err
		}
		if !reprobeHas(r, QueryNetkit) {
			return false, noReprobe(QueryNetkit)
		}
		return r.(NetkitCaps).HasNetkit(direction)
	}
	return c.boolean(QueryNetkit, direction)
}

func (r *Recorder) HasNetkit(direction string) (bool, error) {
	if !validNetkitDirection(direction) {
		return false, fmt.Errorf("netkit: unknown direction %q", direction)
	}
	n, ok := capsAs[NetkitCaps](r.under, QueryNetkit)
	if !ok {
		return r.recBool(QueryNetkit, direction, false, unknownErr("no netkit probe"))
	}
	v, err := n.HasNetkit(direction)
	return r.recBool(QueryNetkit, direction, v, err)
}

func checkRecordedNetkit(c *RecordedCaps) error {
	for _, queries := range []map[string]map[string]Answer{c.Queries, c.PrivilegedQueries} {
		answers, present := queries[QueryNetkit]
		if !present {
			continue
		}
		if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit {
			return keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryNetkit, recordedFormatNetkit, c.Format)
		}
		keys := make([]string, 0, len(answers))
		for d := range answers {
			keys = append(keys, d)
		}
		sort.Strings(keys)
		for _, d := range keys {
			a := answers[d]
			if !validNetkitDirection(d) {
				return fmt.Errorf("caps: netkit: unknown direction %q", d)
			}
			if a.Value == nil && a.Unknown == "" && a.Error == "" {
				return fmt.Errorf("caps: netkit %q is not a value answer", d)
			}
		}
	}
	return nil
}
