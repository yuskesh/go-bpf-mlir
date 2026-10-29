package gobpf

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// The nosuid hint is added after the probe EPERM hint only when all three facts hold (the file has capabilities, they are not effective, the executable's mount is nosuid).
// If any one is missing, only the existing hint is given (no guessed hint). The facts are injected through capFacts.
func TestNosuidHint(t *testing.T) {
	saved := capFacts
	defer func() { capFacts = saved }()
	const capBPF, capNetAdmin = uint64(1) << 39, uint64(1) << 12
	for _, c := range []struct {
		name                string
		fileCaps, effective uint64
		nosuid, ok, want    bool
	}{
		{"all three facts", capBPF | capNetAdmin, 0, true, true, true},
		{"not nosuid", capBPF | capNetAdmin, 0, false, true, false},
		{"no file capabilities", 0, 0, true, true, false},
		{"file capabilities in effect", capBPF | capNetAdmin, capBPF | capNetAdmin, true, true, false},
		{"facts unreadable", capBPF | capNetAdmin, 0, true, false, false},
	} {
		capFacts = func() (string, uint64, uint64, bool, bool) {
			return "/mnt/myprog", c.fileCaps, c.effective, c.nosuid, c.ok
		}
		reset(t)
		Register(exampleObject(t))
		_, _, err := Load(probeErr)
		var he *HintError
		if !errors.As(err, &he) || !strings.HasPrefix(he.Hint, hintProbePermission) {
			t.Fatalf("%s: the probe hint must stay first, got %v", c.name, err)
		}
		got := strings.Contains(he.Hint, "nosuid mount")
		if got != c.want {
			t.Errorf("%s: nosuid hint present=%v, want %v:\n%s", c.name, got, c.want, he.Hint)
		}
	}
}

// TestNosuidHintLive (the real measurement): only with GOBPF_NOSUID_LIVE=1 — runs a test binary with file capabilities (setcap) on a nosuid mount
// as an ordinary user and calls the checked Load without touching the rlimit. The probe EPERM must carry the nosuid hint.
func TestNosuidHintLive(t *testing.T) {
	if os.Getenv("GOBPF_NOSUID_LIVE") != "1" {
		t.Skip("GOBPF_NOSUID_LIVE=1 with this test binary copied to a nosuid mount, setcap'ed and run as a normal user")
	}
	exe, fileCaps, effective, nosuid, ok := capFacts()
	t.Logf("facts: exe=%s fileCaps=%#x effective=%#x nosuid=%v ok=%v", exe, fileCaps, effective, nosuid, ok)
	reset(t)
	Register(exampleObject(t))
	_, _, err := Load(livecaps.New())
	t.Logf("Load: %v", err)
	var he *HintError
	if !errors.As(err, &he) || !strings.Contains(he.Hint, "nosuid mount") {
		t.Fatalf("want the nosuid hint on the probe's EPERM, got %v", err)
	}
}
