package gobpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// cgroupAttachTypes maps (kind, attach) to the kernel attach type (the same pairs as bpf-mlir's ProgramAttaches.def).
var cgroupAttachTypes = map[[2]string]ebpf.AttachType{
	{"cgroup_skb", "ingress"}:            ebpf.AttachCGroupInetIngress,
	{"cgroup_skb", "egress"}:             ebpf.AttachCGroupInetEgress,
	{"cgroup_sock", "sock_create"}:       ebpf.AttachCGroupInetSockCreate,
	{"cgroup_sock", "sock_release"}:      ebpf.AttachCgroupInetSockRelease,
	{"cgroup_sock", "post_bind4"}:        ebpf.AttachCGroupInet4PostBind,
	{"cgroup_sock", "post_bind6"}:        ebpf.AttachCGroupInet6PostBind,
	{"cgroup_sock_addr", "bind4"}:        ebpf.AttachCGroupInet4Bind,
	{"cgroup_sock_addr", "bind6"}:        ebpf.AttachCGroupInet6Bind,
	{"cgroup_sock_addr", "connect4"}:     ebpf.AttachCGroupInet4Connect,
	{"cgroup_sock_addr", "connect6"}:     ebpf.AttachCGroupInet6Connect,
	{"cgroup_sock_addr", "sendmsg4"}:     ebpf.AttachCGroupUDP4Sendmsg,
	{"cgroup_sock_addr", "sendmsg6"}:     ebpf.AttachCGroupUDP6Sendmsg,
	{"cgroup_sock_addr", "recvmsg4"}:     ebpf.AttachCGroupUDP4Recvmsg,
	{"cgroup_sock_addr", "recvmsg6"}:     ebpf.AttachCGroupUDP6Recvmsg,
	{"cgroup_sock_addr", "getpeername4"}: ebpf.AttachCgroupInet4GetPeername,
	{"cgroup_sock_addr", "getpeername6"}: ebpf.AttachCgroupInet6GetPeername,
	{"cgroup_sock_addr", "getsockname4"}: ebpf.AttachCgroupInet4GetSockname,
	{"cgroup_sock_addr", "getsockname6"}: ebpf.AttachCgroupInet6GetSockname,
	{"sock_ops", ""}:                     ebpf.AttachCGroupSockOps,
	{"cgroup_device", ""}:                ebpf.AttachCGroupDevice,
	{"cgroup_sysctl", ""}:                ebpf.AttachCGroupSysctl,
	// cgroup_sockopt: the hook is the directive
	{"cgroup_sockopt", "getsockopt"}: ebpf.AttachCGroupGetsockopt,
	{"cgroup_sockopt", "setsockopt"}: ebpf.AttachCGroupSetsockopt,
}

// AttachCgroup attaches a cgroup-family program (cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops — a function value) to the cgroup v2 directory cgroupDir
// (cilium's link.AttachCgroup; the attach type follows from the program's kind and hook — the context type and the directive).
// It also applies to processes in child cgroups (cgroup v2 inheritance). A non-root loader needs CAP_BPF + CAP_NET_ADMIN and write permission on the directory.
// lsm_cgroup uses the same entry (attach type AttachLSMCgroup — the hook is the directive); a non-root loader needs CAP_BPF + CAP_PERFMON (load).
func AttachCgroup(o *Objects, fn any, cgroupDir string) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil {
		return nil, fmt.Errorf("gobpf.AttachCgroup: the function is not a program of the embedded object")
	}
	at, ok := cgroupAttachTypes[[2]string{e.Kind, e.Attach}]
	if e.Kind == "lsm_cgroup" { // the hook is the directive (the attach type does not depend on the hook)
		at, ok = ebpf.AttachLSMCgroup, true
	}
	if !ok {
		return nil, wantKind(e, "cgroup_skb", "gobpf.AttachCgroup")
	}
	l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupDir, Attach: at, Program: p})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachCgroup: program %s (%s %s) at %s: %w", e.Symbol, e.Kind, e.Attach, cgroupDir, err)
	}
	return l, nil
}

// AttachNetNs attaches an sk_lookup program (a function value) to the netns at a netns path (such as /run/netns/<name> or /proc/<pid>/ns/net) (cilium's
// link.AttachNetNs, BPF_LINK_CREATE). The program runs **only for lookups in that netns**. A non-root loader needs CAP_BPF (load) and the ability to open the netns
// file.
func AttachNetNs(o *Objects, fn any, netnsPath string) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil {
		return nil, fmt.Errorf("gobpf.AttachNetNs: the function is not a program of the embedded object")
	}
	if e.Kind != "sk_lookup" && e.Kind != "flow_dissector" { // flow_dissector: one per netns
		return nil, wantKind(e, "sk_lookup", "gobpf.AttachNetNs")
	}
	f, err := os.Open(netnsPath)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachNetNs: open the netns %s: %w", netnsPath, err)
	}
	defer f.Close()
	l, err := link.AttachNetNs(int(f.Fd()), p)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachNetNs: program %s at %s: %w", e.Symbol, netnsPath, err)
	}
	return l, nil
}

// ReuseportLink is an sk_reuseport attach (SO_ATTACH_REUSEPORT_EBPF — attached to a socket's SO_REUSEPORT group). Close is SO_DETACH_REUSEPORT_BPF
// (closing every socket in the group also detaches it).
type ReuseportLink struct{ fd int }

// Close detaches the program from the group (through the attached socket's fd — ENOENT if the group has no program).
func (l *ReuseportLink) Close() error {
	return unix.SetsockoptInt(l.fd, unix.SOL_SOCKET, unix.SO_DETACH_REUSEPORT_BPF, 0)
}

// AttachReuseport attaches an sk_reuseport program (a function value) to the group of a bound SO_REUSEPORT socket fd with SO_ATTACH_REUSEPORT_EBPF
// (cilium has no entry for it, so gobpf calls setsockopt). The program runs **only for selections in that group**. Before bind, or on a socket without SO_REUSEPORT,
// it is EINVAL. A non-root loader needs only CAP_BPF (load) — attaching needs no capability.
func AttachReuseport(o *Objects, fn any, fd int) (*ReuseportLink, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil {
		return nil, fmt.Errorf("gobpf.AttachReuseport: the function is not a program of the embedded object")
	}
	if e.Kind != "sk_reuseport" {
		return nil, wantKind(e, "sk_reuseport", "gobpf.AttachReuseport")
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, p.FD()); err != nil {
		return nil, fmt.Errorf("gobpf.AttachReuseport: program %s at socket fd %d: %w", e.Symbol, fd, err)
	}
	return &ReuseportLink{fd: fd}, nil
}

// SocketFilterLink is a socket_filter attach (SO_ATTACH_BPF). Close is SO_DETACH_BPF (closing the socket also detaches it).
type SocketFilterLink struct{ fd int }

// Close detaches the program from the socket.
func (l *SocketFilterLink) Close() error {
	return unix.SetsockoptInt(l.fd, unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
}

// AttachSocketFilter attaches a socket_filter program (a function value) to a socket fd with SO_ATTACH_BPF. The program runs for each received packet,
// and a packet with the verdict SocketDrop does not reach the socket. A non-root loader needs CAP_BPF (program load) — the socket's owner can attach it.
func AttachSocketFilter(o *Objects, fn any, fd int) (*SocketFilterLink, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "socket_filter", "gobpf.AttachSocketFilter"); err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, p.FD()); err != nil {
		return nil, fmt.Errorf("gobpf.AttachSocketFilter: program %s on fd %d: %w", e.Symbol, fd, err)
	}
	return &SocketFilterLink{fd: fd}, nil
}
