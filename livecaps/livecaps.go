//go:build linux

// Package livecaps exposes capabilities of the running kernel through the
// shared internal/kload implementation, without duplicating checks. It also
// exposes tracepoint attachment from internal/tpattach. This glue belongs in
// the kernel module: bindrt remains stdlib-only apart from requirements/layout,
// and generated bindings need not duplicate cilium or perf-event code.
package livecaps

import (
	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/kload"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/tpattach"
)

// LiveCaps is the same capability implementation shared by runners and callers.
type LiveCaps = kload.LiveCaps

// New returns capabilities for the running kernel.
func New() LiveCaps { return LiveCaps{} }

// TracepointOptions controls AttachTracepointAllCPUs.
type TracepointOptions = tpattach.Options

// TracepointLink owns all CPU events and the program link. BPF exposes the link,
// CPUs lists opened CPUs, and Close releases everything.
type TracepointLink = tpattach.Link

// AttachTracepointAllCPUs opens pid -1 events on all online CPUs but attaches
// the program only to the first: a second attachment of the same program gets
// EEXIST. Unlike cilium v0.22's CPU-0-only event, this handles 7.1.8 syscall
// tracepoints reading user memory on any CPU. Refuse possible != online unless
// OnlineOnly is chosen; CPUs brought online later remain unobserved. Requires
// root for reading tracefs IDs and opening pid -1 perf events.
func AttachTracepointAllCPUs(group, name string, prog *ebpf.Program, opts *TracepointOptions) (*TracepointLink, error) {
	return tpattach.Attach(group, name, prog, opts)
}
