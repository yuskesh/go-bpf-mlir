//go:build linux

// Package tpattach attaches tracepoint programs with perf events on all online
// CPUs. kernel/livecaps provides the public facade. On 7.1.8 syscall events
// reading user memory run BPF only if that CPU's perf-event hlist is nonempty;
// cilium v0.22 link.Tracepoint opens an event on CPU 0 only.
// Attach the program only to the first CPU event: a second attachment of the
// same program fails with EEXIST because the tracepoint has one prog_array.
// Keep the other CPU events open without programs to populate their hlists;
// the shared prog_array still runs BPF once per syscall.
package tpattach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Options controls optional attachment behavior.
type Options struct {
	// OnlineOnly explicitly permits possible != online, opening current online
	// CPUs only. Otherwise refuse: offline CPUs return ENODEV and CPUs brought
	// online later would silently lack an event.
	OnlineOnly bool
}

// Link owns all CPU perf events and the program link for one tracepoint.
// Close releases them all.
type Link struct {
	bpf  link.Link
	fds  []int
	cpus []int
}

// BPF exposes the first CPU's program link for ID inspection. Close via Link.
func (l *Link) BPF() link.Link { return l.bpf }

// CPUs returns opened event CPU numbers in ascending order.
func (l *Link) CPUs() []int { return append([]int(nil), l.cpus...) }

// Close releases the link and every event, returning the first error after
// attempting all closes. Repeated calls do nothing.
func (l *Link) Close() error {
	var first error
	if l.bpf != nil {
		first = l.bpf.Close()
		l.bpf = nil
	}
	for _, fd := range l.fds {
		if err := unix.Close(fd); err != nil && first == nil {
			first = err
		}
	}
	l.fds = nil
	return first
}

// ValidName uses cilium tracefs name rules, rejecting empty, '/' and '..' path input.
func ValidName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ParseCPUList parses possible/online CPU lists such as 0-3,5,7-8 into sorted CPUs.
func ParseCPUList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty cpu list")
	}
	var out []int
	last := -1
	for _, part := range strings.Split(s, ",") {
		lo, hi, rng := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return nil, fmt.Errorf("bad cpu list %q", s)
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil, fmt.Errorf("bad cpu list %q", s)
			}
		}
		if a <= last {
			return nil, fmt.Errorf("cpu list %q is not ascending", s)
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
		last = b
	}
	return out, nil
}

// SelectCPUs refuses offline CPUs unless OnlineOnly explicitly selects the
// current online set.
func SelectCPUs(possible, online []int, onlineOnly bool) ([]int, error) {
	on := map[int]bool{}
	for _, c := range online {
		on[c] = true
	}
	var off []string
	for _, c := range possible {
		if !on[c] {
			off = append(off, strconv.Itoa(c))
		}
	}
	if len(off) > 0 && !onlineOnly {
		return nil, fmt.Errorf("possible CPUs %s are offline: an event opened now would miss them if they come online (set OnlineOnly to open on the online CPUs only)", strings.Join(off, ","))
	}
	if len(online) == 0 {
		return nil, errors.New("no online CPU")
	}
	return append([]int(nil), online...), nil
}

var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// EventID reads tracefs events/<group>/<name>/id.
func EventID(group, name string) (uint64, error) {
	if !ValidName(group) || !ValidName(name) {
		return 0, fmt.Errorf("tracepoint %q/%q: names must be [A-Za-z0-9_]+", group, name)
	}
	var errs []error
	for _, root := range tracefsRoots {
		p := filepath.Join(root, "events", group, name, "id")
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", p, err)
		}
		return id, nil
	}
	return 0, fmt.Errorf("tracepoint %s/%s: %w", group, name, errors.Join(errs...))
}

func readCPUs(path string) ([]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l, err := ParseCPUList(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// Attach opens events on all selected CPUs and attaches to <group>/<name>.
// Failure closes everything already opened.
func Attach(group, name string, prog *ebpf.Program, opts *Options) (*Link, error) {
	if prog == nil {
		return nil, errors.New("tpattach: nil program")
	}
	if opts == nil {
		opts = &Options{}
	}
	id, err := EventID(group, name)
	if err != nil {
		return nil, err
	}
	possible, err := readCPUs("/sys/devices/system/cpu/possible")
	if err != nil {
		return nil, err
	}
	online, err := readCPUs("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	cpus, err := SelectCPUs(possible, online, opts.OnlineOnly)
	if err != nil {
		return nil, fmt.Errorf("tracepoint %s/%s: %w", group, name, err)
	}
	l := &Link{cpus: cpus}
	for _, cpu := range cpus {
		// Match cilium openTracepointPerfEvent: PERF_SAMPLE_RAW, sample/wakeup 1,
		// enabled, pid -1 for all tasks and an explicit CPU.
		attr := unix.PerfEventAttr{Type: unix.PERF_TYPE_TRACEPOINT, Config: id, Sample_type: unix.PERF_SAMPLE_RAW, Sample: 1, Wakeup: 1}
		attr.Size = uint32(unsafe.Sizeof(attr))
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("tracepoint %s/%s: perf_event_open on CPU %d: %w", group, name, cpu, err)
		}
		l.fds = append(l.fds, fd)
	}
	lk, err := link.AttachRawLink(link.RawLinkOptions{Target: l.fds[0], Program: prog, Attach: ebpf.AttachPerfEvent})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("tracepoint %s/%s: link on CPU %d: %w", group, name, cpus[0], err)
	}
	l.bpf = lk
	return l, nil
}
