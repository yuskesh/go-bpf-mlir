package gobpf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/internal/uprobeabi"
)

// LoadOption is an extra input to Load.
type LoadOption func(*loadConfig)

type loadConfig struct {
	uprobePaths map[uintptr]string // program function (value pointer) → the binary's path at run time
	debugRoot   *string            // WithUprobeDebugRoot (nil — not given)
	debugFiles  map[uintptr]string // program function (value pointer) → its separate debug file (WithUprobeDebugFile)
}

// WithUprobeDebugRoot sets the root of the build ID lookup of separate DWARF for the uprobe targets of Load: a target without .debug_info is
// checked against <dir>/.build-id/<xx>/<rest>.debug (bound by its GNU build ID and the CRC32 of its .gnu_debuglink — bpf-mlir's pre-load
// check). "" turns the lookup off. **Without this option the root is the live caps' UprobeDebugRoot — nil means /usr/lib/debug.** Giving
// both this option and a non-nil UprobeDebugRoot in the caps is an error (Load does not pick one).
func WithUprobeDebugRoot(dir string) LoadOption {
	return func(c *loadConfig) {
		c.debugRoot = &dir
	}
}

// WithUprobeDebugFile passes the separate debug file of the target of the uprobe (or uretprobe, uprobe_multi, uretprobe_multi) program fn. It
// replaces the build ID lookup for that program (a file that cannot be read is not followed by the lookup) and is bound by the same build ID and
// CRC32 check. fn needs a WithUprobeTarget, and the caps must not already name a file for the same program.
func WithUprobeDebugFile(fn any, path string) LoadOption {
	return func(c *loadConfig) {
		if c.debugFiles == nil {
			c.debugFiles = map[uintptr]string{}
		}
		if v := reflect.ValueOf(fn); v.Kind() == reflect.Func {
			c.debugFiles[v.Pointer()] = path
		}
	}
}

// WithUprobeTarget passes to Load the **run-time path** of the target binary of the uprobe (and uretprobe) program fn. With the fd opened from that path, Load
// checks the binary's sha256 (the hash at generation — the schema's binary_sha256) and the symbol before load, passes the same fd to bpf-mlir's gate (Precheck — verdict version 4 from v0.14.0:
// **the calling convention (the DWARF compilation unit's language — a Go function stops with uprobearg_abi)** and the argument types), and keeps it until AttachUprobe — the check and the attach
// see the same file (inode) (the path is never reopened). An object with uprobe programs needs a target for every uprobe program.
func WithUprobeTarget(fn any, path string) LoadOption {
	return func(c *loadConfig) {
		if c.uprobePaths == nil {
			c.uprobePaths = map[uintptr]string{}
		}
		if v := reflect.ValueOf(fn); v.Kind() == reflect.Func {
			c.uprobePaths[v.Pointer()] = path
		}
	}
}

// uprobeTarget is the target of a loaded uprobe program (the open fd and the symbols' file offsets).
type uprobeTarget struct {
	f       *os.File
	path    string
	offsets []uint64 // symbol file offsets (one for a single uprobe, in list order for multi)
}

// uprobeCaps is the live caps plus the uprobe binaries (the hashed fds — requirements.UprobeBinaries). It embeds LiveCaps, so
// other queries are unchanged.
type uprobeCaps struct {
	livecaps.LiveCaps
	bins        map[string]*os.File // program symbol → fd
	gobpfLoader bool                // the object also has ksyscall programs — Loader() returns gobpf's declaration
}

// Loader is the loader declaration (requirements.LoaderCaps) — gobpf's declaration for an object with ksyscall programs, otherwise the live caps' declaration.
func (c uprobeCaps) Loader() requirements.LoaderDecl {
	if c.gobpfLoader {
		return LoaderDecl
	}
	return c.LiveCaps.Loader()
}

// UprobeBinary returns the fd of the program's target (requirements.UprobeBinaries).
func (c uprobeCaps) UprobeBinary(program string) (io.ReaderAt, error) {
	f, ok := c.bins[program]
	if !ok {
		return nil, fmt.Errorf("no uprobe target for program %s", program)
	}
	return f, nil
}

// prepareUprobes opens and checks the targets of the uprobe programs and adds them to caps. Without uprobe programs it returns caps unchanged.
func prepareUprobes(obj *Object, caps requirements.Capabilities, cfg loadConfig, wantSHA map[string]string) (requirements.Capabilities, map[string]*uprobeTarget, error) {
	targets := map[string]*uprobeTarget{}
	closeAll := func() {
		for _, t := range targets {
			t.f.Close()
		}
	}
	for _, p := range obj.Programs {
		if p.Kind != "uprobe" && p.Kind != "uretprobe" && p.Kind != "uprobe_multi" && p.Kind != "uretprobe_multi" && p.Kind != "usdt" { // uretprobe, multi and usdt use the same target check
			continue
		}
		path, ok := cfg.uprobePaths[reflect.ValueOf(p.Func).Pointer()]
		if !ok {
			closeAll()
			return nil, nil, fmt.Errorf("gobpf.Load: uprobe program %s (%s) needs its target binary — pass gobpf.WithUprobeTarget(%s, <path>)", p.Symbol, p.Attach, p.Symbol)
		}
		f, err := os.Open(path)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("gobpf.Load: uprobe program %s: %w", p.Symbol, err)
		}
		targets[p.Symbol] = &uprobeTarget{f: f, path: path}
		// Only sha256 and the attach file offset — the calling convention (Go functions) and the argument types are checked by bpf-mlir's gate (since v0.14.0) (Precheck's uprobearg_abi /
		// uprobearg) on the same fd (up to v0.13.0 gobpf also checked them with internal/uprobeabi.Inspect).
		if p.Kind == "usdt" {
			// usdt checks only sha256 (the points' file offsets and specs come from the glue — livecaps.AttachUSDT reads the notes from the same fd; the points, semaphores and arguments are
			// checked by Precheck's usdt check on the same fd).
			h := sha256.New()
			if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gobpf.Load: usdt program %s, target %s: %w", p.Symbol, path, err)
			}
			if sha, want := hex.EncodeToString(h.Sum(nil)), wantSHA[p.Symbol]; sha != want {
				closeAll()
				return nil, nil, fmt.Errorf("gobpf.Load: usdt program %s: the target %s has SHA-256 %s, but the object was generated for %s (a different build of the binary — regenerate against it)", p.Symbol, path, sha, want)
			}
			continue
		}
		// multi has a file offset per symbol in the list (the same fd — one sha256).
		for _, sym := range strings.Fields(p.Attach) {
			sha, off, err := uprobeabi.Locate(f, sym)
			if err != nil {
				closeAll()
				return nil, nil, fmt.Errorf("gobpf.Load: uprobe program %s, target %s: %w", p.Symbol, path, err)
			}
			if want := wantSHA[p.Symbol]; sha != want {
				closeAll()
				return nil, nil, fmt.Errorf("gobpf.Load: uprobe program %s: the target %s has SHA-256 %s, but the object was generated for %s (a different build of the binary — regenerate against it)", p.Symbol, path, sha, want)
			}
			targets[p.Symbol].offsets = append(targets[p.Symbol].offsets, off)
		}
	}
	if len(targets) == 0 {
		if cfg.debugRoot != nil || len(cfg.debugFiles) > 0 {
			return nil, nil, fmt.Errorf("gobpf.Load: WithUprobeDebugRoot / WithUprobeDebugFile given, but the object has no uprobe program")
		}
		return caps, nil, nil
	}
	lc, ok := caps.(livecaps.LiveCaps)
	if !ok {
		closeAll()
		return nil, nil, fmt.Errorf("gobpf.Load: uprobe targets need the live caps (livecaps.New()) — got %T", caps)
	}
	lc, err := withDebugOptions(obj, lc, cfg)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	bins := map[string]*os.File{}
	for s, t := range targets {
		bins[s] = t.f
	}
	return uprobeCaps{LiveCaps: lc, bins: bins}, targets, nil
}

// withDebugOptions puts WithUprobeDebugRoot and WithUprobeDebugFile into a copy of the live caps (the caller's map is not changed). A field the
// caps already set and an option for the same thing is an error, as is a debug file for a function that is not a uprobe program with a target.
func withDebugOptions(obj *Object, lc livecaps.LiveCaps, cfg loadConfig) (livecaps.LiveCaps, error) {
	if cfg.debugRoot != nil {
		if lc.UprobeDebugRoot != nil {
			return lc, fmt.Errorf("gobpf.Load: WithUprobeDebugRoot(%q) given, but the caps already set UprobeDebugRoot to %q — set one of them", *cfg.debugRoot, *lc.UprobeDebugRoot)
		}
		root := *cfg.debugRoot
		lc.UprobeDebugRoot = &root
	}
	if len(cfg.debugFiles) == 0 {
		return lc, nil
	}
	paths := map[string]string{}
	for p, path := range lc.UprobeDebugPaths {
		paths[p] = path
	}
	for fn, path := range cfg.debugFiles {
		var prog *Program
		for i := range obj.Programs {
			p := &obj.Programs[i]
			if reflect.ValueOf(p.Func).Pointer() == fn && p.Kind != "usdt" && cfg.uprobePaths[fn] != "" {
				prog = p
			}
		}
		if prog == nil {
			return lc, fmt.Errorf("gobpf.Load: WithUprobeDebugFile(%s) names a function that is not a uprobe program with a WithUprobeTarget", path)
		}
		if old, ok := paths[prog.Symbol]; ok {
			return lc, fmt.Errorf("gobpf.Load: WithUprobeDebugFile(%s, %s) given, but the caps already name %s for it — set one of them", prog.Symbol, path, old)
		}
		paths[prog.Symbol] = path
	}
	lc.UprobeDebugPaths = paths
	return lc, nil
}

// UprobeTarget is AttachUprobe's run-time input (the binary is the fd passed to Load with WithUprobeTarget).
type UprobeTarget struct {
	// PID is the process to attach to (0 means every process).
	PID int
}

// AttachUprobe attaches a uprobe program (a function value) to the entry of the symbol in the binary given to Load's WithUprobeTarget. The file offset
// passed is computed from the fd Load checked (cilium never reopens the path), and after attaching it confirms the link info (the perf uprobe's
// file offset), closing the link with an error if it differs. A non-root loader needs CAP_SYS_ADMIN.
func AttachUprobe(o *Objects, fn any, t UprobeTarget) (link.Link, error) {
	return attachUserProbe(o, fn, t, "uprobe", "gobpf.AttachUprobe")
}

// AttachUretprobe attaches a uretprobe program (a function value) to the return of the symbol in the binary given to Load's WithUprobeTarget (the same
// fd and file offset check and link info confirmation as AttachUprobe). The target's calling convention (SysV only — a Go function stops with uretprobe_abi) is checked by Load's
// check. A non-root loader needs CAP_SYS_ADMIN (the same as uprobe).
func AttachUretprobe(o *Objects, fn any, t UprobeTarget) (link.Link, error) {
	return attachUserProbe(o, fn, t, "uretprobe", "gobpf.AttachUretprobe")
}

// attachUserProbe is the shared uprobe / uretprobe attach procedure (kind picks entry or return).
func attachUserProbe(o *Objects, fn any, t UprobeTarget, kind, api string) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, kind, api); err != nil {
		return nil, err
	}
	ut := o.uprobes[e.Symbol]
	if ut == nil {
		return nil, fmt.Errorf("%s: program %s has no target — load with gobpf.Load(caps, gobpf.WithUprobeTarget(%s, <path>))", api, e.Symbol, e.Symbol)
	}
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", ut.f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s: program %s: %w", api, e.Symbol, err)
	}
	offset := ut.offsets[0]
	opts := &link.UprobeOptions{Address: offset, PID: t.PID}
	var l link.Link
	if kind == "uretprobe" {
		l, err = ex.Uretprobe(e.Attach, p, opts)
	} else {
		l, err = ex.Uprobe(e.Attach, p, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: program %s at %s (offset %#x in %s): %w", api, e.Symbol, e.Attach, offset, ut.path, err)
	}
	info, err := l.Info()
	if err != nil || info.PerfEvent() == nil || info.PerfEvent().Uprobe() == nil {
		l.Close()
		return nil, fmt.Errorf("%s: program %s: cannot confirm the attach point (link info: %v)", api, e.Symbol, err)
	}
	if got := uint64(info.PerfEvent().Uprobe().Offset); got != offset {
		l.Close()
		return nil, fmt.Errorf("%s: program %s was attached at offset %#x, not the checked %#x of %s; detached", api, e.Symbol, got, offset, e.Attach)
	}
	return l, nil
}

// UprobeMultiLink is the link from AttachUprobeMulti and whether its attach target could be checked with the kernel's link info.
type UprobeMultiLink struct {
	link.Link
	// Verified reports whether, after attaching, the link info's offsets, cookies and pid were confirmed to match the passed values. false means the kernel does not report
	// uprobe_multi link info (before 6.8 — the 6.6 series), so it could not be checked (the offsets passed are computed from the fd Load checked).
	Verified bool
}

// AttachUprobeMulti attaches a uprobe_multi / uretprobe_multi program (a function value) to the list of symbols in the binary given to Load's WithUprobeTarget with one link
// (cilium's Executable.UprobeMulti / UretprobeMulti). **The order and numbering of the list follow the mtarget order in the embedded ELF's requirements** —
// symbol i gets cookie i (bpf.ProbeTargetIndex returns i). Addresses are file offsets computed from the fd Load checked (cilium never reopens
// the binary — the same as a single uprobe); t.PID is the process to attach to (0 means every process). After attaching it reads the link info; if the kernel
// reports offsets, cookies and pid it checks them against the passed values (closing the link with an error if they differ), and on a kernel that does not (6.6) it returns Verified false without checking
// (not an error — uprobe_multi works on 6.6). A non-root loader needs CAP_BPF + CAP_PERFMON (the kernel has no extra capability check for creating the link).
func AttachUprobeMulti(o *Objects, fn any, t UprobeTarget) (*UprobeMultiLink, error) {
	const api = "gobpf.AttachUprobeMulti"
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil || (e.Kind != "uprobe_multi" && e.Kind != "uretprobe_multi") {
		return nil, wantKind(e, "uprobe_multi", api)
	}
	parsed, err := parsedOf(o.obj)
	if err != nil {
		return nil, err
	}
	var syms []string
	for _, a := range parsed.Requirements().Attaches {
		if a.Program == e.Symbol {
			syms = a.MTargets
		}
	}
	ut := o.uprobes[e.Symbol]
	if ut == nil {
		return nil, fmt.Errorf("%s: program %s has no target — load with gobpf.Load(caps, gobpf.WithUprobeTarget(%s, <path>))", api, e.Symbol, e.Symbol)
	}
	// The list is in the ELF's mtarget order — it must be the same list as the offsets of Load's check (the schema's attach_target order) (a difference means a missed regeneration).
	if strings.Join(syms, " ") != e.Attach || len(ut.offsets) != len(syms) {
		return nil, fmt.Errorf("%s: program %s: the embedded ELF's mtarget rows %v differ from the generated list %q (regenerate with go generate)", api, e.Symbol, syms, e.Attach)
	}
	ex, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", ut.f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s: program %s: %w", api, e.Symbol, err)
	}
	cookies := make([]uint64, len(syms))
	for i := range cookies {
		cookies[i] = uint64(i)
	}
	opts := &link.UprobeMultiOptions{Addresses: ut.offsets, Cookies: cookies, PID: uint32(t.PID)}
	var l link.Link
	if e.Kind == "uretprobe_multi" {
		l, err = ex.UretprobeMulti(nil, p, opts)
	} else {
		l, err = ex.UprobeMulti(nil, p, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: program %s at %v (offsets %#x in %s): %w", api, e.Symbol, syms, ut.offsets, ut.path, err)
	}
	info, err := l.Info()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("%s: program %s: link info: %w", api, e.Symbol, err)
	}
	um := info.UprobeMulti()
	if um == nil || um.Count == 0 {
		return &UprobeMultiLink{Link: l}, nil // the kernel does not report uprobe_multi link info (6.6) — cannot check
	}
	offs, ok := um.Offsets()
	pid, _ := um.Pid()
	bad := !ok || len(offs) != len(syms) || pid != uint32(t.PID)
	for i := 0; !bad && i < len(offs); i++ {
		bad = offs[i].Offset != ut.offsets[i] || offs[i].Cookie != cookies[i]
	}
	if bad {
		l.Close()
		return nil, fmt.Errorf("%s: program %s: the link reports offsets/cookies %+v and pid %d, not the checked offsets %#x, cookies 0..%d and pid %d; detached", api, e.Symbol, offs, pid, ut.offsets, len(syms)-1, t.PID)
	}
	return &UprobeMultiLink{Link: l, Verified: true}, nil
}
