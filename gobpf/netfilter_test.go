package gobpf

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The netns inode check before a netfilter link is attached (the reviewer's guard) — a unit test without root.
func TestNetnsCheck(t *testing.T) {
	for _, c := range []struct {
		name                 string
		target, thread, host uint64
		want                 string // part of the error text ("" means nil)
	}{
		{"host-inode", 7, 7, 7, "is the host netns"},             // the same inode — do not attach to the host's hook
		{"thread-elsewhere", 7, 9, 3, "is not the target netns"}, // setns did not take effect
		{"test-netns", 7, 7, 3, ""},
	} {
		err := netnsCheck(c.target, c.thread, c.host)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: want nil, got %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
	}
}

// TestNetnsGuardRefusesOwnNetns: passing the test process's own netns (the host netns) as the target is stopped by the guard — as root with "host netns",
// without root with "cannot confirm" because /proc/1/ns/net is unreadable; neither attaches.
func TestNetnsGuardRefusesOwnNetns(t *testing.T) {
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	err = netnsGuard(fd)
	if err == nil {
		t.Fatal("netnsGuard accepted the process's own (host) netns")
	}
	if !strings.Contains(err.Error(), "is the host netns") && !strings.Contains(err.Error(), "cannot read the host netns") {
		t.Fatalf("unexpected guard error: %v", err)
	}
	t.Logf("refused: %v", err)
}
