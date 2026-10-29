package gobpf

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/internal/nsguard"
)

// AttachNetfilter attaches a netfilter program (a function value) to the pf / hook of the netns at a netns path (such as /var/run/netns/<name>) with a priority
// (cilium's link.AttachNetfilter). **The kernel attaches to the hook of the netns of the thread that creates the link**, so gobpf locks an OS thread,
// setns into that netns, and **right before attaching** confirms that the thread's netns inode equals the given netns inode and differs from the
// host netns (/proc/1/ns/net) inode (otherwise an error without attaching — the reviewer's guard: never attach to the host's hook). If /proc/1/ns/net is unreadable it does not attach (cannot confirm).
// After attaching it returns to the original netns (if it cannot, the thread is discarded while still locked — Go does not reuse it). A non-root loader needs CAP_BPF +
// CAP_NET_ADMIN (+ CAP_PERFMON for reading through state / skb), the ability to open the netns file, and CAP_SYS_ADMIN for setns.
func AttachNetfilter(o *Objects, fn any, netnsPath string, pf link.NetfilterProtocolFamily, hook link.NetfilterInetHook, priority int32) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil {
		return nil, fmt.Errorf("gobpf.AttachNetfilter: the function is not a program of the embedded object")
	}
	if e.Kind != "netfilter" {
		return nil, wantKind(e, "netfilter", "gobpf.AttachNetfilter")
	}
	type res struct {
		l   link.Link
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- res{nil, fmt.Errorf("gobpf.AttachNetfilter: open the thread's netns: %w", err)}
			return
		}
		defer unix.Close(orig)
		target, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- res{nil, fmt.Errorf("gobpf.AttachNetfilter: open the netns %s: %w", netnsPath, err)}
			return
		}
		defer unix.Close(target)
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			ch <- res{nil, fmt.Errorf("gobpf.AttachNetfilter: setns %s: %w", netnsPath, err)}
			return
		}
		var l link.Link
		aerr := netnsGuard(target)
		if aerr == nil {
			l, aerr = link.AttachNetfilter(link.NetfilterOptions{Program: p, ProtocolFamily: pf, Hook: hook, Priority: priority})
			if aerr != nil {
				aerr = fmt.Errorf("gobpf.AttachNetfilter: program %s at %s pf %d hook %d priority %d: %w", e.Symbol, netnsPath, pf, hook, priority, aerr)
			}
		} else {
			aerr = fmt.Errorf("gobpf.AttachNetfilter: %s: %w (not attached)", netnsPath, aerr)
		}
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			ch <- res{l, errors.Join(aerr, fmt.Errorf("gobpf.AttachNetfilter: setns back: %w (the thread stays locked and is discarded)", err))}
			return
		}
		runtime.UnlockOSThread()
		ch <- res{l, aerr}
	}()
	r := <-ch
	return r.l, r.err
}

// netnsGuard runs on the thread after setns, reads the inodes of the thread's netns, the given netns fd and the host netns (/proc/1/ns/net), and calls netnsCheck
// (the guard itself is internal/nsguard — shared with the seg6local route).
func netnsGuard(target int) error { return nsguard.Guard(target) }

// netnsCheck is the netns inode guard: the thread's netns is the given netns, and it is not the host netns.
func netnsCheck(target, thread, host uint64) error { return nsguard.Check(target, thread, host) }
