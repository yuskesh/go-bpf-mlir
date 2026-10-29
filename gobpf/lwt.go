package gobpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/internal/nsguard"
)

// Attaching an lwt route encap. The rtnetlink assembly follows the same layout as bpf-mlir v1.11.0's kernel/cmd/attachcheck
// netlink, lwt route and attribute builders (the shape that passed on all three kernels — copied, not imported, because it is package main):
// rtmsg (AF_INET, dst_len, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_LINK, RTN_UNICAST) with RTA_DST, RTA_OIF, RTA_ENCAP_TYPE =
// LWTUNNEL_ENCAP_BPF, and inside RTA_ENCAP (| NLA_F_NESTED) LWT_BPF_IN / OUT / XMIT (| NLA_F_NESTED) holding LWT_BPF_PROG_FD (u32) and
// LWT_BPF_PROG_NAME (NUL-terminated). netnsGuard runs before sending (the same idea as attachcheck's host netns check — never send in the host netns).

// UAPI values (include/uapi/linux/lwtunnel.h — those missing from x/sys, copied from bpf-mlir's attachcheck).
const (
	lwtBpfIn       = 1    // LWT_BPF_IN
	lwtBpfOut      = 2    // LWT_BPF_OUT
	lwtBpfXmit     = 3    // LWT_BPF_XMIT
	lwtBpfProgFD   = 1    // LWT_BPF_PROG_FD
	lwtBpfProgName = 2    // LWT_BPF_PROG_NAME
	rtaEncap       = 0x16 // RTA_ENCAP
)

// LWTRoute is an lwt route in a test netns. Close deletes the route in the same netns (RTM_DELROUTE).
type LWTRoute struct {
	netnsPath string
	dst       *net.IPNet
	oif       int
}

// AttachLWTRoute adds the route `<dst> dev <oif> encap bpf [in <in>] [out <out>] [xmit <xmit>]` in the netns at netnsPath (RTM_NEWROUTE with
// CREATE|EXCL — fnIn / fnOut / fnXmit are function values, nil for unused stages). It sends only after netnsGuard passes on the setns thread (the thread's netns = the given netns, ≠ the host's
// /proc/1/ns/net). dst is IPv4. A non-root loader needs CAP_BPF + CAP_NET_ADMIN (load), CAP_NET_ADMIN in the netns (route) and
// CAP_SYS_ADMIN for setns.
func AttachLWTRoute(o *Objects, netnsPath string, dst *net.IPNet, oif string, fnIn, fnOut, fnXmit any) (*LWTRoute, error) {
	var encap []byte
	for _, s := range []struct {
		fn   any
		typ  uint16
		kind string
	}{{fnIn, lwtBpfIn, "lwt_in"}, {fnOut, lwtBpfOut, "lwt_out"}, {fnXmit, lwtBpfXmit, "lwt_xmit"}} {
		if s.fn == nil {
			continue
		}
		p, err := o.Program(s.fn)
		if err != nil {
			return nil, err
		}
		e := o.entryOf(s.fn)
		if e == nil || e.Kind != s.kind {
			return nil, fmt.Errorf("gobpf.AttachLWTRoute: the %s stage takes a %s program", s.kind, s.kind)
		}
		encap = append(encap, lwtProgAttr(s.typ, p, e.Symbol)...)
	}
	if encap == nil {
		return nil, errors.New("gobpf.AttachLWTRoute: no program (In, Out or Xmit)")
	}
	r := &LWTRoute{netnsPath: netnsPath, dst: dst}
	err := inNetns(netnsPath, func() error {
		ifc, err := net.InterfaceByName(oif)
		if err != nil {
			return err
		}
		r.oif = ifc.Index
		et := make([]byte, 2)
		binary.NativeEndian.PutUint16(et, unix.LWTUNNEL_ENCAP_BPF)
		body := concat(lwtRouteBase(dst, r.oif), nlAttr(unix.RTA_ENCAP_TYPE, et), nlAttr(rtaEncap|unix.NLA_F_NESTED, encap))
		return rtNetlink(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
	})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachLWTRoute: %s %s dev %s: %w", netnsPath, dst, oif, err)
	}
	return r, nil
}

// Close deletes the route (RTM_DELROUTE in the same netns — with the guard).
func (r *LWTRoute) Close() error {
	return inNetns(r.netnsPath, func() error {
		return rtNetlink(unix.RTM_DELROUTE, 0, lwtRouteBase(r.dst, r.oif))
	})
}

// lwtProgAttr is PROG_FD and PROG_NAME inside LWT_BPF_<typ> (| NLA_F_NESTED) (copied from bpf-mlir's attachcheck).
func lwtProgAttr(typ uint16, p *ebpf.Program, name string) []byte {
	return nlAttr(typ|unix.NLA_F_NESTED, concat(
		nlAttr(lwtBpfProgFD, u32(uint32(p.FD()))),
		nlAttr(lwtBpfProgName, append([]byte(name), 0)),
	))
}

// lwtRouteBase is the rtmsg with RTA_DST and RTA_OIF (copied from bpf-mlir's attachcheck — the dst length comes from the dst mask).
func lwtRouteBase(dst *net.IPNet, oif int) []byte {
	ones, _ := dst.Mask.Size()
	rtm := make([]byte, unix.SizeofRtMsg)
	rtm[0] = unix.AF_INET
	rtm[1] = byte(ones)
	rtm[4] = unix.RT_TABLE_MAIN
	rtm[5] = unix.RTPROT_BOOT
	rtm[6] = unix.RT_SCOPE_LINK
	rtm[7] = unix.RTN_UNICAST
	return concat(rtm, nlAttr(unix.RTA_DST, dst.IP.To4()), nlAttr(unix.RTA_OIF, u32(uint32(oif))))
}

// nlAttr is an rtattr (len, type, 4-byte alignment — copied from bpf-mlir's attachcheck).
func nlAttr(typ uint16, payload []byte) []byte {
	l := unix.SizeofRtAttr + len(payload)
	b := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(b[0:], uint16(l))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[unix.SizeofRtAttr:], payload)
	return b
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, v); return b }

func concat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

// rtNetlink sends one request to NETLINK_ROUTE in the current thread's netns and returns the ack's error (copied from bpf-mlir's attachcheck — the guard is the caller's
// inNetns, before sending).
func rtNetlink(typ, flags uint16, body []byte) error {
	msg := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.SizeofNlMsghdr+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], typ)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|flags)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	s, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	if err := unix.Sendto(s, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(s, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_ERROR && len(m.Data) >= 4 {
			if e := int32(binary.NativeEndian.Uint32(m.Data[:4])); e != 0 {
				return fmt.Errorf("rtnetlink %d: %w", typ, unix.Errno(-e))
			}
			return nil
		}
	}
	return fmt.Errorf("rtnetlink %d: no ack", typ)
}

// inNetns locks an OS thread, setns into the netns at netnsPath, runs f only after netnsGuard passes, and returns to the original netns
// (if it cannot, the thread is discarded while still locked — the implementation is internal/nsguard.In).
func inNetns(netnsPath string, f func() error) error { return nsguard.In(netnsPath, f) }
