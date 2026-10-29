//go:build linux

package livecaps

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// SockmapProgAttachLoader declares cilium v0.22 plus this PROG_ATTACH glue.
// Caller caps.Loader() must return it; default LiveCaps declares link and
// rejects kernels lacking sockmap links. This is an explicit choice, not an
// automatic fallback. See docs/requirements_format.md section 8.
var SockmapProgAttachLoader = requirements.Cilium022ProgAttach

// SockmapProgAttach owns a BPF_PROG_ATTACH association with no link FD.
// Close must BPF_PROG_DETACH; otherwise the program stays until the map's last
// reference disappears.
type SockmapProgAttach struct {
	prog   *ebpf.Program
	sock   *ebpf.Map
	attach ebpf.AttachType
	closed bool
}

// AttachSockmapProgAttach uses BPF_PROG_ATTACH for sk_skb/sk_msg on sockmap or
// sockhash via cilium RawAttachProgram. PROG_ATTACH exists since 4.17; sockmap
// BPF_LINK_CREATE since 6.10. attach must equal the program's loaded
// expected_attach_type. Precheck with SockmapProgAttachLoader first. Requires
// root or CAP_NET_ADMIN and CAP_BPF.
func AttachSockmapProgAttach(prog *ebpf.Program, sock *ebpf.Map, attach ebpf.AttachType) (*SockmapProgAttach, error) {
	if prog == nil || sock == nil {
		return nil, errors.New("AttachSockmapProgAttach: nil program or map")
	}
	switch prog.Type() {
	case ebpf.SkSKB, ebpf.SkMsg:
	default:
		return nil, fmt.Errorf("AttachSockmapProgAttach: program type %v is not sk_skb / sk_msg", prog.Type())
	}
	switch sock.Type() {
	case ebpf.SockMap, ebpf.SockHash:
	default:
		return nil, fmt.Errorf("AttachSockmapProgAttach: map type %v is not sockmap / sockhash", sock.Type())
	}
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: sock.FD(), Program: prog, Attach: attach}); err != nil {
		return nil, fmt.Errorf("BPF_PROG_ATTACH %v to %v: %w", attach, sock.Type(), err)
	}
	return &SockmapProgAttach{prog: prog, sock: sock, attach: attach}, nil
}

// Close detaches once with BPF_PROG_DETACH; repeated calls do nothing.
func (s *SockmapProgAttach) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	return link.RawDetachProgram(link.RawDetachProgramOptions{Target: s.sock.FD(), Program: s.prog, Attach: s.attach})
}
