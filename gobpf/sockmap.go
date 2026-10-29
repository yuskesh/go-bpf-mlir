package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// sockmapAttachTypes maps each kind that attaches to a sockmap to its attach type (the same as the requirements' attach row — the expected_attach_type the program was loaded with).
var sockmapAttachTypes = map[string]ebpf.AttachType{"sk_skb": ebpf.AttachSkSKBStreamVerdict, "sk_msg": ebpf.AttachSkMsgVerdict}

// AttachSockmap attaches an sk_skb or sk_msg program (a function value) to the sockmap / sockhash in its directive `//gobpf:sk_skb <map>` with **BPF_PROG_ATTACH**
// (bpf-mlir's livecaps.AttachSockmapProgAttach. BPF_LINK_CREATE for a sockmap exists from 6.10 — 6.6 cannot create the link; PROG_ATTACH exists from
// 4.17). Close on the result detaches with BPF_PROG_DETACH. **PROG_ATTACH holds no fd** — even without Close, the program is detached when the map goes away (when all user
// references to the map are closed). The program runs only on receives of sockets put in the map. Pass only programs loaded by Load (Load
// checks the gobpf declaration — sockmap_attach prog_attach). A non-root loader needs CAP_BPF and CAP_NET_ADMIN (or CAP_SYS_ADMIN).
func AttachSockmap(o *Objects, fn any) (*livecaps.SockmapProgAttach, error) {
	const api = "gobpf.AttachSockmap"
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	at, ok := ebpf.AttachType(0), false
	if e != nil {
		at, ok = sockmapAttachTypes[e.Kind]
	}
	if !ok {
		return nil, wantKind(e, "sk_skb", api)
	}
	m := o.coll.Maps[e.Attach]
	if m == nil {
		return nil, fmt.Errorf("%s: program %s: the object has no map %s (its //gobpf:%s directive — regenerate with go generate)", api, e.Symbol, e.Attach, e.Kind)
	}
	l, err := livecaps.AttachSockmapProgAttach(p, m, at)
	if err != nil {
		return nil, fmt.Errorf("%s: program %s to %s: %w", api, e.Symbol, e.Attach, err)
	}
	return l, nil
}
