package gobpf

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// The build with plain upstream cilium/ebpf (no replace — the public form). Fixes present upstream (the arena cast, lsm_cgroup,
// SyscallWrapper) keep the same declaration as the fork; fsession, which only the fork has (upstream PR #2108 — open), stops before load.

// CiliumFork says this is not the fork (the provenance row).
var CiliumFork = "none (upstream cilium/ebpf)"

// CiliumForkPatches is empty (upstream cilium/ebpf has no patches).
var CiliumForkPatches []string

// loaderName is the LoaderDecl name (it appears in the check's messages — kept apart from the fork build's "cilium-v0.22-gobpf").
const loaderName = "cilium-upstream-gobpf"

// fsessionLoad is the LoaderDecl's fsession_load — upstream cilium/ebpf cannot load fsession programs. gobpf.Load and CheckTarget refuse
// an object with an fsession program with the bindrt check's Unmet `fsession_loader` (stops the load).
const fsessionLoad = requirements.ProgLoadNone

// errNoFsession is the error when an fsession attach is requested in a build with upstream cilium/ebpf.
var errNoFsession = errors.New("fsession needs a cilium/ebpf with fsession support (upstream PR #2108); this gobpf was built with upstream cilium/ebpf")

// fsessionAttachType is always an error in the upstream build (Load stops first, so this is normally not reached).
func fsessionAttachType() (ebpf.AttachType, error) { return 0, errNoFsession }
