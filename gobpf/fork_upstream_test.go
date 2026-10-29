package gobpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// The expected LoaderDecl of the build on plain upstream cilium/ebpf.
const (
	wantLoaderName   = "cilium-upstream-gobpf"
	wantFsessionLoad = requirements.ProgLoadNone // upstream cannot load fsession (PR #2108 is open)
)

// The plain upstream build says in its provenance that it is not the fork, and asking for the fsession attach type is a named error.
func TestUpstreamCiliumBuild(t *testing.T) {
	if CiliumFork != "none (upstream cilium/ebpf)" || len(CiliumForkPatches) != 0 {
		t.Fatalf("the upstream cilium build must say it is not the fork: %q %v", CiliumFork, CiliumForkPatches)
	}
	if _, err := fsessionAttachType(); !errors.Is(err, errNoFsession) || !strings.Contains(err.Error(), "PR #2108") {
		t.Fatalf("fsessionAttachType must refuse with errNoFsession naming PR #2108, got %v", err)
	}
}
