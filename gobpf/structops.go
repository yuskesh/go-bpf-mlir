package gobpf

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
)

// struct_ops (bpf.TCPCongestionOps): gobpf.Load creates the struct_ops map and writes the program fds into the value (the fork cilium's
// populateStructOps), but the map is BPF_F_LINK (ELF section `.struct_ops.link`), so the kernel only checks the value and **does not register it**
// (the early BPF_F_LINK return in bpf_struct_ops_map_update_elem in kernel/bpf/bpf_struct_ops.c). Registration is AttachStructOps' link
// (BPF_LINK_CREATE → st_ops->reg); closing the link unregisters it (unregistering can lag — there is a gap until the name leaves the available list).

// structOpsVar is the Go variable of a struct_ops map (bpf.TCPCongestionOps).
type structOpsVar interface {
	GobpfStructOps() (typ, name string)
}

// tcpAvailablePath is the list of registered TCP congestion control names (tcp_available_congestion_control in net/ipv4/sysctl_net_ipv4.c).
var tcpAvailablePath = "/proc/sys/net/ipv4/tcp_available_congestion_control"

// TCPCongestionAvailable reports whether name is in the list of registered TCP congestion control names.
func TCPCongestionAvailable(name string) (bool, error) {
	b, err := os.ReadFile(tcpAvailablePath)
	if err != nil {
		return false, err
	}
	for _, f := range strings.Fields(string(b)) {
		if f == name {
			return true, nil
		}
	}
	return false, nil
}

// AttachStructOps registers a struct_ops map (a pointer to the Go variable, such as &CC) with a link (cilium's link.AttachStructOps).
// **Registration is system-wide** — the tcp_congestion_ops becomes one of the kernel's TCP congestion control names, and sockets in every netns can pick it with setsockopt
// TCP_CONGESTION (picking needs CAP_NET_ADMIN — flags 0). After registering it confirms the name is in tcp_available_congestion_control,
// and closes the link with an error if not. If the same name already exists, the kernel returns −EEXIST (an error creating the link).
func AttachStructOps(o *Objects, mapVar any) (link.Link, error) {
	if o.closed {
		return nil, fmt.Errorf("gobpf.AttachStructOps: Objects is closed")
	}
	sv, ok := mapVar.(structOpsVar)
	if !ok {
		return nil, fmt.Errorf("gobpf.AttachStructOps: %T is not a struct_ops map variable (pass &CC for var CC = bpf.TCPCongestionOps{…})", mapVar)
	}
	typ, name := sv.GobpfStructOps()
	var sym string
	for _, m := range o.obj.Maps {
		if m.Var == mapVar {
			sym = m.Symbol
		}
	}
	if sym == "" {
		return nil, fmt.Errorf("gobpf.AttachStructOps: the variable is not a map of the embedded object")
	}
	km := o.coll.Maps[sym]
	if km == nil {
		return nil, fmt.Errorf("gobpf.AttachStructOps: the embedded ELF has no struct_ops map %s (regenerate with go generate)", sym)
	}
	l, err := link.AttachStructOps(link.StructOpsOptions{Map: km})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachStructOps: registering %s %q (map %s): %w", typ, name, sym, err)
	}
	if typ == "tcp_congestion_ops" {
		in, err := TCPCongestionAvailable(name)
		if err != nil || !in {
			l.Close()
			return nil, fmt.Errorf("gobpf.AttachStructOps: %s %q is not in %s after the link (err %v); detached", typ, name, tcpAvailablePath, err)
		}
	}
	return l, nil
}
