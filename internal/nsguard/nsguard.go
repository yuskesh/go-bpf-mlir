// Package nsguard is the netns inode guard applied before attaching to or sending into a test netns (gobpf's AttachNetfilter and
// AttachLWTRoute, and the route of mutation runs that do not use gobpf objects, all go through the same function).
package nsguard

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Guard reads, on the thread after setns, the inodes of the thread's netns, the given netns fd and the host netns (/proc/1/ns/net), and runs Check.
func Guard(target int) error {
	var st unix.Stat_t
	if err := unix.Fstat(target, &st); err != nil {
		return fmt.Errorf("stat the target netns: %w", err)
	}
	t := st.Ino
	if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
		return fmt.Errorf("stat the thread's netns: %w", err)
	}
	th := st.Ino
	if err := unix.Stat("/proc/1/ns/net", &st); err != nil {
		return fmt.Errorf("cannot read the host netns /proc/1/ns/net to check the target is not the host's: %w", err)
	}
	return Check(t, th, st.Ino)
}

// Check is the netns inode guard: the thread's netns must be the given netns and must not be the host netns.
func Check(target, thread, host uint64) error {
	if thread != target {
		return fmt.Errorf("the thread's netns (inode %d) is not the target netns (inode %d)", thread, target)
	}
	if target == host {
		return fmt.Errorf("the target netns (inode %d) is the host netns (/proc/1/ns/net) — a netfilter link or a route there would change the host's traffic", target)
	}
	return nil
}

// In locks the OS thread, setns into the netns at netnsPath, runs f only if Guard passes, and returns to the original netns
// (if it cannot return, the thread stays locked and is discarded).
func In(netnsPath string, f func() error) error {
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("open the thread's netns: %w", err)
			return
		}
		defer unix.Close(orig)
		target, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("open the netns %s: %w", netnsPath, err)
			return
		}
		defer unix.Close(target)
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("setns %s: %w", netnsPath, err)
			return
		}
		ferr := Guard(target)
		if ferr == nil {
			ferr = f()
		} else {
			ferr = fmt.Errorf("%w (nothing sent)", ferr)
		}
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			ch <- errors.Join(ferr, fmt.Errorf("setns back: %w (the thread stays locked and is discarded)", err))
			return
		}
		runtime.UnlockOSThread()
		ch <- ferr
	}()
	return <-ch
}
