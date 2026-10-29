package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// LoaderDecl is gobpf's loader declaration (bpf-mlir's requirements_format.md): the preset cilium-v0.22-usdt-ksyscall (cilium v0.22 with **ksyscall_attach
// changed to prefix and usdt_attach to ref_ctr**) with **sockmap_attach changed to prog_attach, lsm_cgroup_load to btf_id
// (the local cilium fork looks up the BTF id through upstream PR #2115), and fsession_load to btf_id (PR #2108)**. cilium v0.22 fails to attach to the bare name
// after `ksyscall/<name>` in the section (declared none), does not attach USDT points (declared none), and attaches to a sockmap with a link (kernels before 6.10
// have no sockmap link), but gobpf attaches to `__x64_sys_<name>` itself in AttachKsyscall, attaches with bpf-mlir's glue in AttachUSDT (livecaps.AttachUSDT —
// declared ref_ctr, the same as livecaps.USDTLoader), and attaches with BPF_PROG_ATTACH in AttachSockmap (livecaps.AttachSockmapProgAttach — declared
// prog_attach, the same as livecaps.SockmapProgAttachLoader) — the declaration matches how it attaches. For an object with ksyscall, usdt or sk_skb programs,
// the check (Load, CheckTarget) sets the caps' Loader() to this declaration. Other objects are checked with the caps' own declaration (Cilium022).
// ksyscall_attach and usdt_attach come from bpf-mlir's preset `cilium-v0.22-usdt-ksyscall` (requirements.Cilium022USDTKsyscall — it differs from Cilium022
// only in ksyscall_attach, which is prefix, and usdt_attach, which is ref_ctr), and the attaches are livecaps.AttachKsyscall and livecaps.AttachUSDT — the declared values are the same as before.
var LoaderDecl = func() requirements.LoaderDecl {
	d := requirements.Cilium022USDTKsyscall
	d.Name = loaderName
	d.SockmapAttach = livecaps.SockmapProgAttachLoader.SockmapAttach // AttachSockmap uses PROG_ATTACH (6.6 has no sockmap link)
	d.LSMCgroupLoad = requirements.ProgLoadBTFID                     // the cilium fork (v0.22.0-gobpf.3 — upstream PR #2115) loads with the BTF id of bpf_lsm_<hook>
	d.FsessionLoad = fsessionLoad                                    // the cilium fork (v0.22.0-gobpf.4 — upstream PR #2108) loads with the function's BTF id; the plain upstream build has none
	return d
}()

// ksysCaps is the live caps with Loader() set to gobpf's declaration (it embeds LiveCaps, so other queries are unchanged).
type ksysCaps struct {
	livecaps.LiveCaps
}

// Loader is gobpf's declaration (requirements.LoaderCaps).
func (ksysCaps) Loader() requirements.LoaderDecl { return LoaderDecl }

// needsGobpfLoader reports whether the object has a program that needs gobpf's declaration (ksyscall, usdt).
func needsGobpfLoader(o *Object) bool {
	for _, p := range o.Programs {
		if p.Kind == "ksyscall" || p.Kind == "usdt" || p.Kind == "sk_skb" || p.Kind == "sk_msg" || p.Kind == "lsm_cgroup" || p.Kind == "fsession" { // sk_skb / sk_msg: sockmap_attach prog_attach; lsm_cgroup / fsession: *_load btf_id
			return true
		}
	}
	return false
}

// withGobpfLoader sets the check caps' Loader() to gobpf's declaration for an object with ksyscall or usdt programs (the live caps and the uprobe caps —
// other caps (recorded caps and so on) are unchanged: the caller's declaration is respected).
func withGobpfLoader(o *Object, caps requirements.Capabilities) requirements.Capabilities {
	if !needsGobpfLoader(o) {
		return caps
	}
	switch c := caps.(type) {
	case livecaps.LiveCaps:
		return ksysCaps{LiveCaps: c}
	case uprobeCaps:
		c.gobpfLoader = true
		return c
	}
	return caps
}

// AttachKsyscall attaches a ksyscall program (a function value) to the entry of the syscall wrapper `__x64_sys_<syscall>` for the syscall in its directive `//gobpf:ksyscall <syscall>`.
// The attach is bpf-mlir's livecaps.AttachKsyscall: the wrapper name comes from **the kernel's machine (uname)** and
// requirements.KsyscallWrapper (the same source as Load's check checkKsyscall — earlier it was built from the user-space GOARCH with the cilium fork's link.SyscallWrapper),
// an unknown prefix is an error before attaching, it attaches with cilium's link.Kprobe, and **it compares the attached target (the function name in the perf kprobe link's info) with
// the wrapper name, closing the link with an error if they differ** (cilium silently re-attaches to an alias when it cannot attach — the same reason as attach_alias).
// The error is `gobpf.AttachKsyscall: program <symbol>: <livecaps message>`. The link applies system-wide (it hooks the syscall of every process — read-only).
// Pass only programs loaded by Load (Load checks the wrapper's existence and the argument types (sysarg) — sysarg reads tracefs, so a non-root
// Load cannot decide and stops). A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachKsyscall(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "ksyscall", "gobpf.AttachKsyscall"); err != nil {
		return nil, err
	}
	return attachKsyscallEntry(e.Symbol, e.Attach, p, attachKsyscallLive)
}

// attachKsyscallLive is bpf-mlir's glue (tests replace it — to test the wrapping of the stop message).
var attachKsyscallLive = livecaps.AttachKsyscall

// attachKsyscallEntry attaches with the live glue and wraps the error with gobpf.AttachKsyscall and the program symbol.
func attachKsyscallEntry(symbol, syscall string, p *ebpf.Program, live func(*ebpf.Program, string) (link.Link, error)) (link.Link, error) {
	l, err := live(p, syscall)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachKsyscall: program %s: %w", symbol, err)
	}
	return l, nil
}
