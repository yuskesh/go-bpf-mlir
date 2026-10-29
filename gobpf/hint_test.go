package gobpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// A hint is added to known non-root loader failures, and the original error type and errno stay reachable with errors.As / errors.Is (no root needed).
func TestLoadHints(t *testing.T) {
	// The probe's EPERM (the same shape as probeErrCaps in bpf-mlir's precheck_test.go) — Load adds a hint to the *PrecheckError.
	reset(t)
	Register(exampleObject(t))
	_, _, err := Load(probeErr)
	var he *HintError
	var pe *PrecheckError
	var ve *ebpf.VerifierError
	if !errors.As(err, &he) || he.Hint != hintProbePermission {
		t.Fatalf("the probe's EPERM needs the CAP_BPF / CAP_NET_ADMIN hint, got %v", err)
	}
	if !errors.As(err, &pe) || !errors.As(err, &ve) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("the original *PrecheckError / *VerifierError / EPERM must stay reachable: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "hint: ") || !strings.HasPrefix(err.Error(), pe.Error()) {
		t.Fatalf("the hint is appended after the original message:\n%v", err)
	}
	t.Logf("probe EPERM:\n%v", err)

	// The verifier's !root refusal (a measured log line) — the CAP_PERFMON hint.
	vErr := fmt.Errorf("program Sample: load program: %w", &ebpf.VerifierError{Cause: syscall.EACCES, Log: []string{"112: (0f) r2 += r1", "R2 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root"}})
	got := withHint(vErr)
	if !errors.As(got, &he) || he.Hint != hintPerfmon || !errors.As(got, &ve) || !errors.Is(got, syscall.EACCES) {
		t.Fatalf("the !root verifier refusal needs the CAP_PERFMON hint and must keep *VerifierError: %v", got)
	}

	// Unknown errors are returned unchanged (no hint).
	for _, e := range []error{
		errors.New("something else"),
		&ebpf.VerifierError{Cause: syscall.EINVAL, Log: []string{"invalid mem access 'scalar'"}},
		&PrecheckError{Err: errors.New("no capabilities given (the check is not skipped)")},
	} {
		if got := withHint(e); got != e {
			t.Errorf("an unknown error must be returned unchanged, got %v", got)
		}
	}
}

// With the actual verifier messages saved on all three kernels (the {CAP_BPF, CAP_NET_ADMIN} logs of flowsample, voff and pkt) as input,
// this pins that the CAP_PERFMON hint appears — so the hint never disappears silently when the matched strings change.
func TestHintOnSavedVerifierLogs(t *testing.T) {
	n := 0
	for _, k := range []string{"7.1.8", "6.12.111", "6.6.157"} {
		for _, item := range []string{"flowsample", "voff", "pkt"} {
			path := filepath.Join(repoRoot(), "gobpf", "testdata", "verifierlog", "nonroot", "run", k, "bpf+net_admin", item+".log")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var line string
			for _, l := range strings.Split(string(b), "\n") {
				if strings.Contains(l, "permission denied") {
					line = l
					break
				}
			}
			if line == "" {
				t.Fatalf("%s: no verifier refusal in the saved log", path)
			}
			// The shape of a cilium VerifierError log line (the text after "permission denied: " is the last log line).
			logLine := line[strings.Index(line, "permission denied: ")+len("permission denied: "):]
			got := withHint(&ebpf.VerifierError{Cause: syscall.EACCES, Log: []string{logLine}})
			var he *HintError
			if !errors.As(got, &he) || he.Hint != hintPerfmon {
				t.Errorf("%s: the saved %s refusal gets no CAP_PERFMON hint: %q", k, item, logLine)
			}
			n++
		}
	}
	t.Logf("%d saved refusals (3 kernels × flowsample / voff / pkt) all get the CAP_PERFMON hint", n)
}

// The hint for the probe's EPERM is chosen by the object's program kinds — the CAP_PERFMON text with a fentry, the CAP_NET_ADMIN text with only XDP / tcx.
func TestProbeHintByKind(t *testing.T) {
	reset(t)
	Register(Object{Programs: []Program{{Symbol: "p", Kind: "xdp"}}})
	if got := probeHint(); got != hintProbePermission {
		t.Fatalf("xdp object: %q", got)
	}
	reset(t)
	Register(Object{Programs: []Program{{Symbol: "p", Kind: "xdp"}, {Symbol: "f", Kind: "fentry", Attach: "do_sys_poll"}}})
	if got := probeHint(); got != hintProbeFentry {
		t.Fatalf("object with a fentry program: %q", got)
	}
	reset(t)
}

// The refused Go line is extracted from actual verifier logs of all three kernels (saved with %+v — bpf-mlir v0.6.0's line_info).
// 6.6 writes `; f.go:L`, 7.1.8 / 6.12 write `; f.go:L @ f.go:L` — both shapes. Nothing is extracted from a truncated log (no final processed line) or a log without line_info.
func savedVerifierLog(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(), "gobpf", "testdata", "verifierlog", "rejectedat", "logs", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	var log []string
	for _, l := range strings.Split(string(b), "\n")[1:] { // line 1 is the error message; the following tab lines are the verifier log
		if strings.HasPrefix(l, "\t") {
			log = append(log, strings.TrimPrefix(l, "\t"))
		}
	}
	return log
}

func TestRejectedAtOnSavedLogs(t *testing.T) {
	for name, want := range map[string]string{
		"idxdef-6.12.111": "idxdef.go:28", "idxdef-6.6.157": "idxdef.go:28",
		"voff-7.1.8": "voff.go:29", "voff-6.12.111": "voff.go:29", "voff-6.6.157": "voff.go:29",
	} {
		log := savedVerifierLog(t, name)
		got, ok := rejectedAt(log)
		if !ok || got != want {
			t.Errorf("%s: rejectedAt = %q %v, want %q", name, got, ok, want)
		}
		err := withHint(fmt.Errorf("program runProg: load program: %w", &ebpf.VerifierError{Cause: syscall.EACCES, Log: log}))
		if !strings.Contains(err.Error(), "the verifier rejected program runProg at "+want) {
			t.Errorf("%s: the error does not name the Go line: %v", name, err)
		}
		// A truncated log (neither the processed line nor the refusal line) — nothing extracted.
		var cut []string
		for _, l := range log {
			if strings.HasPrefix(strings.TrimSpace(l), "processed ") {
				break
			}
			cut = append(cut, l)
		}
		cut = cut[:len(cut)-2]
		if at, ok := rejectedAt(cut); ok {
			t.Errorf("%s: a truncated log gave %q", name, at)
		}
	}
	// A log without line_info (one line from a bpf-mlir v0.5.0 ELF) — nothing extracted.
	if at, ok := rejectedAt([]string{"28: (0f) r1 += r4", "R1 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root", "processed 29 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0"}); ok {
		t.Errorf("a log without line_info gave %q", at)
	}
}

// cilium's upstream main (64d4fa2f — after v0.22.0) moves the verifier log's `processed N insns` line out of Log into Stats.
// With the same saved logs in the upstream shape (no processed line in Log, present in Stats) the Go line hint still appears, and with no Stats either (truncated) it does not.
func TestRejectedAtWithStatsSplit(t *testing.T) {
	for name, want := range map[string]string{"idxdef-6.12.111": "idxdef.go:28", "voff-7.1.8": "voff.go:29"} {
		var log []string
		stats := ""
		for _, l := range savedVerifierLog(t, name) {
			if strings.HasPrefix(strings.TrimSpace(l), "processed ") {
				stats = l
				continue
			}
			log = append(log, l)
		}
		if stats == "" {
			t.Fatalf("%s: the saved log has no processed line", name)
		}
		err := withHint(fmt.Errorf("program runProg: load program: %w", &ebpf.VerifierError{Cause: syscall.EACCES, Log: log, Stats: stats}))
		if !strings.Contains(err.Error(), "the verifier rejected program runProg at "+want) {
			t.Errorf("%s: with the processed line in Stats, the error does not name the Go line: %v", name, err)
		}
		cut := withHint(fmt.Errorf("program runProg: load program: %w", &ebpf.VerifierError{Cause: syscall.EACCES, Log: log}))
		if strings.Contains(cut.Error(), "the verifier rejected") {
			t.Errorf("%s: a log with no processed line in Log or Stats (truncated) named a Go line: %v", name, cut)
		}
	}
}
