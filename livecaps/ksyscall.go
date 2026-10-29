//go:build linux

package livecaps

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// KsyscallLoader declares cilium v0.22 plus AttachKsyscall's prefix contract.
// Caller caps.Loader() must return it; default LiveCaps declares ksyscall_attach
// none and blocks these ELFs. This is an explicit choice, never a fallback.
// See docs/requirements_format.md section 8.
var KsyscallLoader = requirements.Cilium022Ksyscall

// Test hooks for kernel machine, kprobe attach and attached function name.
var (
	ksyscallMachine = unameMachine
	ksyscallKprobe  = func(sym string, prog *ebpf.Program) (link.Link, error) { return link.Kprobe(sym, prog, nil) }
	ksyscallTarget  = kprobeLinkTarget
)

func unameMachine() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(u.Machine[:]), nil
}

func kprobeLinkTarget(l link.Link) (string, error) {
	info, err := l.Info()
	if err != nil {
		return "", err
	}
	pe := info.PerfEvent()
	if pe == nil || pe.Kprobe() == nil {
		return "", fmt.Errorf("link %v is not a perf-event kprobe link", info.Type)
	}
	return pe.Kprobe().Function, nil
}

// AttachKsyscall attaches section ksyscall/<syscall> to <prefix>sys_<syscall>.
// Select the prefix from kernel uname, not loader GOARCH, using the same
// requirements.KsyscallWrapper as precheck. Unknown machines fail before attach.
// cilium Kprobe can retry __x64_ aliases; inspect the actual link function name
// and close/refuse on mismatch or unreadable info. Callers must precheck with
// KsyscallLoader first (sysarg needs readable tracefs). Attachment observes
// system-wide syscalls; the read-only program must filter its own tasks.
func AttachKsyscall(prog *ebpf.Program, syscall string) (link.Link, error) {
	if prog == nil {
		return nil, errors.New("AttachKsyscall: nil program")
	}
	return attachKsyscall(prog.Type(), prog, syscall)
}

func attachKsyscall(typ ebpf.ProgramType, prog *ebpf.Program, syscall string) (link.Link, error) {
	if typ != ebpf.Kprobe {
		return nil, fmt.Errorf("AttachKsyscall: program type %v is not kprobe (ksyscall)", typ)
	}
	if syscall == "" {
		return nil, errors.New("AttachKsyscall: empty syscall name")
	}
	machine, err := ksyscallMachine()
	if err != nil {
		return nil, fmt.Errorf("AttachKsyscall: uname: %w", err)
	}
	want, ok := requirements.KsyscallWrapper(machine, syscall)
	if !ok {
		return nil, fmt.Errorf("AttachKsyscall: no syscall wrapper prefix is known for the kernel machine %q — refusing to attach %s to the bare name", machine, syscall)
	}
	l, err := ksyscallKprobe(want, prog)
	if err != nil {
		return nil, fmt.Errorf("AttachKsyscall: kprobe %s: %w", want, err)
	}
	got, err := ksyscallTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("AttachKsyscall: cannot confirm the attach target %s: %w; detached", want, err)
	}
	if got != want {
		l.Close()
		return nil, fmt.Errorf("AttachKsyscall: attached to %s, not the syscall wrapper %s (the loader substituted another symbol); detached", got, want)
	}
	return l, nil
}
