package nsguard

import (
	"strings"
	"testing"
)

// The route of mutation runs goes through the same guard: given the process's own netns path, In does not run f — as root the guard reports
// "the host netns", as non-root it fails with setns EPERM or an error reading /proc/1/ns/net.
func TestInRefusesOwnNetns(t *testing.T) {
	ran := false
	err := In("/proc/self/ns/net", func() error { ran = true; return nil })
	if ran || err == nil {
		t.Fatalf("In ran f in the process's own netns (ran=%v err=%v)", ran, err)
	}
	if !strings.Contains(err.Error(), "is the host netns") && !strings.Contains(err.Error(), "cannot read the host netns") && !strings.Contains(err.Error(), "setns") {
		t.Fatalf("unexpected refusal: %v", err)
	}
	t.Logf("refused: %v", err)
}

// The three cases of Check (the same as gobpf's TestNetnsCheck).
func TestCheck(t *testing.T) {
	if err := Check(5, 5, 5); err == nil || !strings.Contains(err.Error(), "is the host netns") {
		t.Fatalf("host: %v", err)
	}
	if err := Check(5, 6, 7); err == nil || !strings.Contains(err.Error(), "is not the target netns") {
		t.Fatalf("thread: %v", err)
	}
	if err := Check(5, 5, 7); err != nil {
		t.Fatalf("test netns: %v", err)
	}
}
