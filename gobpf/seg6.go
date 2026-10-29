package gobpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Attaching End.BPF on a seg6local route. The rtnetlink assembly is a copy of bpf-mlir v1.11.0's kernel/cmd/attachcheck
// route builder (rtmsg with AF_INET6, dst_len 128, table, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST + RTA_DST, RTA_OIF,
// RTA_TABLE, RTA_ENCAP_TYPE = LWTUNNEL_ENCAP_SEG6_LOCAL, RTA_ENCAP (| NLA_F_NESTED)) and of its
// End.BPF body (SEG6_LOCAL_ACTION = End.BPF and, inside SEG6_LOCAL_BPF (| NLA_F_NESTED), SEG6_LOCAL_BPF_PROG (the fd as u32) and
// SEG6_LOCAL_BPF_PROG_NAME (NUL-terminated)) (the shape that passed on all three kernels — copied, not imported, because it is package main). nsguard runs before sending.

// UAPI values (include/uapi/linux/seg6_local.h — copied from bpf-mlir's attachcheck).
const (
	seg6LocalAction       = 1  // SEG6_LOCAL_ACTION
	seg6LocalBPF          = 8  // SEG6_LOCAL_BPF
	seg6LocalActionEndBPF = 15 // SEG6_LOCAL_ACTION_END_BPF
	seg6LocalBPFProg      = 1  // SEG6_LOCAL_BPF_PROG
	seg6LocalBPFProgName  = 2  // SEG6_LOCAL_BPF_PROG_NAME
)

// Seg6LocalRoute is a seg6local route in a test netns. Close deletes the route in the same netns (RTM_DELROUTE).
type Seg6LocalRoute struct {
	netnsPath string
	sid       net.IP
	oif       int
}

// AttachSeg6Local attaches an lwt_seg6local program (a function value) to the route `<sid>/128 dev <oif> encap seg6local action End.BPF` in the netns at netnsPath
// (the main table — RTM_NEWROUTE with CREATE|EXCL). It sends only after nsguard passes on the setns thread (the thread's netns = the given netns, ≠ the host's
// /proc/1/ns/net). sid is IPv6. The program name (PROG_NAME) is the ELF symbol. A non-root loader needs CAP_BPF + CAP_NET_ADMIN
// (load), CAP_NET_ADMIN in the netns (route) and CAP_SYS_ADMIN for setns.
func AttachSeg6Local(o *Objects, netnsPath string, sid net.IP, oif string, fn any) (*Seg6LocalRoute, error) {
	if sid.To16() == nil || sid.To4() != nil {
		return nil, fmt.Errorf("gobpf.AttachSeg6Local: the SID %s is not an IPv6 address", sid)
	}
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil || e.Kind != "lwt_seg6local" {
		return nil, fmt.Errorf("gobpf.AttachSeg6Local: takes a lwt_seg6local program")
	}
	encap := concat(
		nlAttr(seg6LocalAction, u32(seg6LocalActionEndBPF)),
		nlAttr(seg6LocalBPF|unix.NLA_F_NESTED, concat(
			nlAttr(seg6LocalBPFProg, u32(uint32(p.FD()))),
			nlAttr(seg6LocalBPFProgName, append([]byte(e.Symbol), 0)),
		)),
	)
	r := &Seg6LocalRoute{netnsPath: netnsPath, sid: sid}
	err = inNetns(netnsPath, func() error {
		ifc, err := net.InterfaceByName(oif)
		if err != nil {
			return err
		}
		r.oif = ifc.Index
		et := make([]byte, 2)
		binary.NativeEndian.PutUint16(et, unix.LWTUNNEL_ENCAP_SEG6_LOCAL)
		body := concat(seg6RouteBase(sid, r.oif), nlAttr(unix.RTA_ENCAP_TYPE, et), nlAttr(rtaEncap|unix.NLA_F_NESTED, encap))
		return rtNetlink(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
	})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachSeg6Local: %s %s/128 dev %s: %w", netnsPath, sid, oif, err)
	}
	return r, nil
}

// Close deletes the route (RTM_DELROUTE in the same netns — with the guard).
func (r *Seg6LocalRoute) Close() error {
	return inNetns(r.netnsPath, func() error {
		return rtNetlink(unix.RTM_DELROUTE, 0, seg6RouteBase(r.sid, r.oif))
	})
}

// seg6RouteBase is the rtmsg with RTA_DST, RTA_OIF and RTA_TABLE (copied from bpf-mlir's attachcheck — the main table).
func seg6RouteBase(sid net.IP, oif int) []byte {
	rtm := make([]byte, unix.SizeofRtMsg)
	rtm[0] = unix.AF_INET6
	rtm[1] = 128
	rtm[4] = unix.RT_TABLE_MAIN
	rtm[5] = unix.RTPROT_BOOT
	rtm[6] = unix.RT_SCOPE_UNIVERSE
	rtm[7] = unix.RTN_UNICAST
	return concat(rtm, nlAttr(unix.RTA_DST, sid.To16()), nlAttr(unix.RTA_OIF, u32(uint32(oif))), nlAttr(unix.RTA_TABLE, u32(unix.RT_TABLE_MAIN)))
}
