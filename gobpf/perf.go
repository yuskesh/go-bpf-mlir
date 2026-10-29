package gobpf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// The perf event reader and the stack trace check at load time.

// PerfReader is the user-space reader of a perf event map (bpf.PerfEventArray[V]): it creates a perf ring for every possible CPU and registers them in the map
// (it wraps cilium's perf.Reader). **Open it before attaching** — gobpf.AttachFentry stops a program that outputs to a map with no open reader.
// Objects.Close also closes open PerfReaders.
type PerfReader[V any] struct {
	m      *bpf.PerfEventArray[V]
	symbol string
	r      *perf.Reader
	rec    Record
	lost   atomic.Uint64
}

// PerfRecord is one result of PerfReader.Read. A result with Lost > 0 is the kernel's overflow notice (PERF_RECORD_LOST — the number dropped in that CPU's ring) and
// has no Value.
type PerfRecord[V any] struct {
	Value V
	CPU   int
	Lost  uint64
}

// perfOpen is the number of open PerfReaders per map symbol (for AttachFentry's check). Guarded by readersMu.
var perfOpen = map[string]int{}

// NewPerfReader creates a reader for a loaded perf event map. pagesPerCPU is the number of ring pages per CPU (at least 1 — cilium rounds up to a power
// of 2). Before load, after Close, or when the generated table has no record for V, it is a named error.
func NewPerfReader[V any](m *bpf.PerfEventArray[V], pagesPerCPU int) (*PerfReader[V], error) {
	km, err := binding.Map(m, "gobpf.NewPerfReader")
	if err != nil {
		return nil, err
	}
	o, err := current()
	if err != nil {
		return nil, err
	}
	sym := binding.Symbol(m)
	want := reflect.TypeFor[V]()
	var rec *Record
	for i := range o.Records {
		if o.Records[i].Type == want {
			rec = &o.Records[i]
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("gobpf.NewPerfReader: perf event array %s: the generated binding has no record for %s (run go generate again)", sym, want)
	}
	if pagesPerCPU < 1 {
		return nil, fmt.Errorf("gobpf.NewPerfReader: perf event array %s: pagesPerCPU must be at least 1, got %d", sym, pagesPerCPU)
	}
	r, err := perf.NewReader(km, pagesPerCPU*os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("gobpf.NewPerfReader: perf event array %s: %w", sym, err)
	}
	rd := &PerfReader[V]{m: m, symbol: sym, r: r, rec: *rec}
	readersMu.Lock()
	readers[rd] = true
	perfOpen[sym]++
	readersMu.Unlock()
	return rd, nil
}

// Read waits for and reads the next result (os.ErrDeadlineExceeded at the SetDeadline deadline). After Close it returns ErrReaderClosed.
func (r *PerfReader[V]) Read() (PerfRecord[V], error) {
	var out PerfRecord[V]
	raw, err := r.r.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return out, fmt.Errorf("perf event array %s: %w", r.symbol, ErrReaderClosed)
		}
		return out, fmt.Errorf("perf event array %s: %w", r.symbol, err)
	}
	out.CPU = raw.CPU
	if raw.LostSamples > 0 {
		r.lost.Add(raw.LostSamples)
		out.Lost = raw.LostSamples
		return out, nil
	}
	d := r.rec.New()
	if err := d.Decode(raw.RawSample); err != nil {
		return out, fmt.Errorf("perf event array %s: %w", r.symbol, err)
	}
	out.Value = reflect.ValueOf(d).Elem().Convert(reflect.TypeFor[V]()).Interface().(V)
	return out, nil
}

// Lost is the sum of the overflow notices read so far. **It can be compared with the eBPF side's count of Output −ENOSPC only after the overflowed ring has been read out and
// the next successful output from the same CPU has been read** (the kernel writes the overflow notice at the next successful write to that ring).
func (r *PerfReader[V]) Lost() uint64 { return r.lost.Load() }

// SetDeadline sets the deadline for Read (the zero value means no deadline).
func (r *PerfReader[V]) SetDeadline(t time.Time) { r.r.SetDeadline(t) }

// Close closes the reader (a second call does nothing). The link stays alive after Close, and outputs to that map fail with −ENOENT (an empty slot).
func (r *PerfReader[V]) Close() error {
	readersMu.Lock()
	if readers[r] {
		delete(readers, r)
		perfOpen[r.symbol]--
	}
	readersMu.Unlock()
	err := r.r.Close()
	if errors.Is(err, perf.ErrClosed) {
		return nil
	}
	return err
}

// requirePerfReaders confirms that a reader is open for every perf event map the program outputs to (never keep dropping silently with
// −ENOENT).
func requirePerfReaders(e *Program, fn string) error {
	if e == nil {
		return nil
	}
	readersMu.Lock()
	defer readersMu.Unlock()
	for _, sym := range e.PerfMaps {
		if perfOpen[sym] == 0 {
			return fmt.Errorf("%s: program %s outputs to the perf event array %s, but no gobpf.NewPerfReader(&%s, …) is open — create the reader before attaching (the kernel drops outputs to an empty CPU slot with −ENOENT)", fn, e.Symbol, sym, sym)
		}
	}
	return nil
}

// perfMaxStackPath is the kernel.perf_event_max_stack sysctl (tests replace it).
var perfMaxStackPath = "/proc/sys/kernel/perf_event_max_stack"

// checkStackDepth compares a stack trace map's Depth with the host's kernel.perf_event_max_stack (the kernel
// refuses with EINVAL to create a stack_trace map whose value size / 8 exceeds the sysctl). If the sysctl is unreadable it says nothing and returns the reason
// (attached to a map creation error).
func checkStackDepth(o *Object) (note string, err error) {
	var stacks []Map
	for _, m := range o.Maps {
		if kd, ok := m.Var.(interface{ GobpfMapKind() string }); ok && kd.GobpfMapKind() == "stack_trace" {
			stacks = append(stacks, m)
		}
	}
	if len(stacks) == 0 {
		return "", nil
	}
	b, rerr := os.ReadFile(perfMaxStackPath)
	if rerr != nil {
		return fmt.Sprintf("stack trace maps need Depth <= kernel.perf_event_max_stack, which could not be read: %v", rerr), nil
	}
	max, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if perr != nil {
		return fmt.Sprintf("stack trace maps need Depth <= kernel.perf_event_max_stack, which could not be parsed: %v", perr), nil
	}
	for _, m := range stacks {
		d := reflect.ValueOf(m.Var).Elem().FieldByName("Depth").Uint()
		if d > max {
			return "", fmt.Errorf("gobpf: stack trace map %s (%s): Depth %d exceeds kernel.perf_event_max_stack %d on this host — lower Depth or raise the sysctl (the kernel refuses the map with EINVAL)", m.Symbol, m.Pos, d, max)
		}
	}
	return fmt.Sprintf("stack trace maps need Depth <= kernel.perf_event_max_stack (%d here)", max), nil
}
