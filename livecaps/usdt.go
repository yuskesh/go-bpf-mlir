//go:build linux

package livecaps

import (
	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/usdtattach"
)

// USDTOptions controls AttachUSDT. PID zero selects all processes.
type USDTOptions = usdtattach.Options

// USDTLink owns point uprobes, offsets and written specs; Close releases all uprobes.
type USDTLink = usdtattach.Link

// USDTPoint describes an attached point; Index is the spec key and cookie.
type USDTPoint = usdtattach.Point

// USDTLoader declares cilium v0.22 plus this ref_ctr glue (specification
// section 8). Precheck caps.Loader() must return it; default LiveCaps does not
// attach USDT and blocks with usdt_loader.
var USDTLoader = requirements.Cilium022USDT

// AttachUSDT reads all <provider>:<name> notes using requirements, writes each
// spec at note-order key i in __ebpf_usdt_spec_<program>, and attaches with
// Address, Cookie i and semaphore RefCtrOffset. Callers must precheck with
// USDTLoader and supply the same inode that was hashed (for example
// /proc/self/fd/N), as required by specification section 8. Root is needed for
// uprobe perf events.
func AttachUSDT(prog *ebpf.Program, specMap *ebpf.Map, binary, provider, name string, opts *USDTOptions) (*USDTLink, error) {
	return usdtattach.Attach(prog, specMap, binary, provider, name, opts)
}

// USDTPoints computes point offsets, semaphore offsets and specs without attaching.
func USDTPoints(binary, provider, name string) ([]USDTPoint, error) {
	return usdtattach.Points(binary, provider, name)
}
