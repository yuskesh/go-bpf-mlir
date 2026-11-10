package frontend

import (
	"go/ast"
	"sort"
	"strings"
)

// Socket and cgroup programs (bpf-mlir's ctx.field / ctx.field.store):
//
//	//gobpf:cgroup_sock_addr connect4
//	func f(ctx *bpf.SockAddrContext) bpf.CgroupAction {
//		p := ctx.UserPort()               → %v = ebpf.ctx.field %ctx "user_port" : !ebpf.ctx<"cgroup_sock_addr"> -> i32
//		ctx.SetUserPort(0xb822)           → ebpf.ctx.field.store %ctx "user_port", %c : !ebpf.ctx<"cgroup_sock_addr">, i32
//		…
//	}
//
// Whether each hook may read / write a field is in ctxAccessRows (a copy of the matching rows of bpf-mlir's ctxaccess.tsv — a test checks it against the submodule's table).

// ctxAccessRow is one row of (kind, bpf-mlir's attach name, field, r / w) (all 4 bytes).
type ctxAccessRow struct{ kind, attach, field, mode string }

// ctxAccessRows are the socket_filter, cgroup_skb, cgroup_sock, cgroup_sock_addr and sock_ops rows of bpf-mlir's ctxaccess.tsv.
var ctxAccessRows = []ctxAccessRow{
	{"cgroup_device", "cgroup_device", "access_type", "r"}, // cgroup_device
	{"cgroup_device", "cgroup_device", "major", "r"},
	{"cgroup_device", "cgroup_device", "minor", "r"},
	{"cgroup_sockopt", "cgroup_getsockopt", "level", "r"}, // cgroup_sockopt
	{"cgroup_sockopt", "cgroup_getsockopt", "optlen", "r"},
	{"cgroup_sockopt", "cgroup_getsockopt", "optlen", "w"},
	{"cgroup_sockopt", "cgroup_getsockopt", "optname", "r"},
	{"cgroup_sockopt", "cgroup_setsockopt", "level", "r"},
	{"cgroup_sockopt", "cgroup_setsockopt", "level", "w"},
	{"cgroup_sockopt", "cgroup_setsockopt", "optlen", "r"},
	{"cgroup_sockopt", "cgroup_setsockopt", "optlen", "w"},
	{"cgroup_sockopt", "cgroup_setsockopt", "optname", "r"},
	{"cgroup_sockopt", "cgroup_setsockopt", "optname", "w"},
	{"sk_reuseport", "sk_reuseport_select", "bind_inany", "r"}, // sk_reuseport (the select_or_migrate rows match bpf-mlir's table — go never emits migrate)
	{"sk_reuseport", "sk_reuseport_select", "eth_protocol", "r"},
	{"sk_reuseport", "sk_reuseport_select", "hash", "r"},
	{"sk_reuseport", "sk_reuseport_select", "ip_protocol", "r"},
	{"sk_reuseport", "sk_reuseport_select", "len", "r"},
	{"sk_reuseport", "sk_reuseport_select_or_migrate", "bind_inany", "r"},
	{"sk_reuseport", "sk_reuseport_select_or_migrate", "eth_protocol", "r"},
	{"sk_reuseport", "sk_reuseport_select_or_migrate", "hash", "r"},
	{"sk_reuseport", "sk_reuseport_select_or_migrate", "ip_protocol", "r"},
	{"sk_reuseport", "sk_reuseport_select_or_migrate", "len", "r"},
	{"sk_lookup", "sk_lookup", "family", "r"}, // sk_lookup
	{"sk_lookup", "sk_lookup", "local_ip4", "r"},
	{"sk_lookup", "sk_lookup", "local_port", "r"},
	{"sk_lookup", "sk_lookup", "protocol", "r"},
	{"sk_lookup", "sk_lookup", "remote_port", "r"},
	{"cgroup_sysctl", "cgroup_sysctl", "file_pos", "r"}, // cgroup_sysctl
	{"cgroup_sysctl", "cgroup_sysctl", "file_pos", "w"},
	{"cgroup_sysctl", "cgroup_sysctl", "write", "r"},
	{"cgroup_skb", "cgroup_inet_egress", "len", "r"},
	{"cgroup_skb", "cgroup_inet_ingress", "len", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_bind", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "type", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_connect", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getpeername", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet4_getsockname", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet6_bind", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_bind", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_bind", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_bind", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet6_connect", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_connect", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_connect", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_connect", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet6_getpeername", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getpeername", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getpeername", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getpeername", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_inet6_getsockname", "family", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getsockname", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getsockname", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_inet6_getsockname", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "family", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_recvmsg", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "family", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "user_ip4", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "user_ip4", "w"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_udp4_sendmsg", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_udp6_recvmsg", "family", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_recvmsg", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_recvmsg", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_recvmsg", "user_port", "w"},
	{"cgroup_sock_addr", "cgroup_udp6_sendmsg", "family", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_sendmsg", "protocol", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_sendmsg", "user_port", "r"},
	{"cgroup_sock_addr", "cgroup_udp6_sendmsg", "user_port", "w"},
	{"cgroup_sock", "cgroup_inet4_post_bind", "family", "r"},
	{"cgroup_sock", "cgroup_inet4_post_bind", "protocol", "r"},
	{"cgroup_sock", "cgroup_inet4_post_bind", "src_ip4", "r"},
	{"cgroup_sock", "cgroup_inet4_post_bind", "src_port", "r"},
	{"cgroup_sock", "cgroup_inet6_post_bind", "family", "r"},
	{"cgroup_sock", "cgroup_inet6_post_bind", "protocol", "r"},
	{"cgroup_sock", "cgroup_inet6_post_bind", "src_port", "r"},
	{"cgroup_sock", "cgroup_inet_sock_create", "family", "r"},
	{"cgroup_sock", "cgroup_inet_sock_create", "mark", "w"},
	{"cgroup_sock", "cgroup_inet_sock_create", "protocol", "r"},
	{"cgroup_sock", "cgroup_inet_sock_create", "type", "r"},
	{"cgroup_sock", "cgroup_inet_sock_release", "family", "r"},
	{"cgroup_sock", "cgroup_inet_sock_release", "protocol", "r"},
	{"socket_filter", "-", "len", "r"},
	{"lwt_in", "-", "len", "r"}, // lwt
	{"lwt_out", "-", "len", "r"},
	{"lwt_xmit", "-", "len", "r"},
	{"lwt_seg6local", "-", "len", "r"}, // lwt_seg6local
	{"lwt_seg6local", "-", "mark", "r"},
	{"lwt_seg6local", "-", "mark", "w"},
	{"lwt_seg6local", "-", "priority", "r"},
	{"lwt_seg6local", "-", "priority", "w"},
	{"lwt_seg6local", "-", "protocol", "r"},
	{"lwt_seg6local", "-", "ifindex", "r"},
	{"sock_ops", "cgroup_sock_ops", "family", "r"},
	{"sock_ops", "cgroup_sock_ops", "local_port", "r"},
	{"sock_ops", "cgroup_sock_ops", "op", "r"},
	{"sock_ops", "cgroup_sock_ops", "remote_port", "r"},
	{"sock_ops", "cgroup_sock_ops", "reply", "w"},
	{"sk_skb", "sk_skb_stream_verdict", "len", "r"}, // sk_skb
	{"sk_skb", "sk_skb_stream_verdict", "local_port", "r"},
	{"sk_skb", "sk_skb_verdict", "len", "r"}, // the verdict attach (not used by a gobpf directive; mirrors bpf-mlir)
	{"sk_skb", "sk_skb_verdict", "local_port", "r"},
	{"sk_skb", "sk_skb_verdict", "remote_port", "r"},
	{"sk_msg", "sk_msg_verdict", "family", "r"}, // sk_msg
	{"sk_msg", "sk_msg_verdict", "local_ip4", "r"},
	{"sk_msg", "sk_msg_verdict", "local_port", "r"},
	{"sk_msg", "sk_msg_verdict", "remote_ip4", "r"},
	{"sk_msg", "sk_msg_verdict", "remote_port", "r"},
	{"sk_msg", "sk_msg_verdict", "size", "r"},
	{"sched_act", "-", "len", "r"}, // sched_act
	{"sched_act", "-", "mark", "w"},
}

// hookAttach maps (kind, the attach of ebpf.program) to bpf-mlir's attach name (the 4th column of ProgramAttaches.def — the attach column of the ctxaccess table).
var hookAttach = map[[2]string]string{
	{"socket_filter", ""}:                "-",
	{"lwt_in", ""}:                       "-",
	{"lwt_out", ""}:                      "-",
	{"lwt_xmit", ""}:                     "-",
	{"lwt_seg6local", ""}:                "-",
	{"cgroup_device", ""}:                "cgroup_device", // cgroup_device
	{"cgroup_sysctl", ""}:                "cgroup_sysctl", // cgroup_sysctl
	{"sk_lookup", ""}:                    "sk_lookup",
	{"sk_reuseport", ""}:                 "sk_reuseport_select",
	{"cgroup_sockopt", "getsockopt"}:     "cgroup_getsockopt",
	{"cgroup_sockopt", "setsockopt"}:     "cgroup_setsockopt",
	{"cgroup_skb", "ingress"}:            "cgroup_inet_ingress",
	{"cgroup_skb", "egress"}:             "cgroup_inet_egress",
	{"cgroup_sock", "sock_create"}:       "cgroup_inet_sock_create",
	{"cgroup_sock", "sock_release"}:      "cgroup_inet_sock_release",
	{"cgroup_sock", "post_bind4"}:        "cgroup_inet4_post_bind",
	{"cgroup_sock", "post_bind6"}:        "cgroup_inet6_post_bind",
	{"cgroup_sock_addr", "bind4"}:        "cgroup_inet4_bind",
	{"cgroup_sock_addr", "bind6"}:        "cgroup_inet6_bind",
	{"cgroup_sock_addr", "connect4"}:     "cgroup_inet4_connect",
	{"cgroup_sock_addr", "connect6"}:     "cgroup_inet6_connect",
	{"cgroup_sock_addr", "sendmsg4"}:     "cgroup_udp4_sendmsg",
	{"cgroup_sock_addr", "sendmsg6"}:     "cgroup_udp6_sendmsg",
	{"cgroup_sock_addr", "recvmsg4"}:     "cgroup_udp4_recvmsg",
	{"cgroup_sock_addr", "recvmsg6"}:     "cgroup_udp6_recvmsg",
	{"cgroup_sock_addr", "getpeername4"}: "cgroup_inet4_getpeername",
	{"cgroup_sock_addr", "getpeername6"}: "cgroup_inet6_getpeername",
	{"cgroup_sock_addr", "getsockname4"}: "cgroup_inet4_getsockname",
	{"cgroup_sock_addr", "getsockname6"}: "cgroup_inet6_getsockname",
	{"sock_ops", ""}:                     "cgroup_sock_ops",
	{"sched_act", ""}:                    "-", // sched_act
}

// sockmapAttach maps a kind attached to a sockmap to bpf-mlir's attach name (the 4th column of ProgramAttaches.def).
var sockmapAttach = map[string]string{"sk_skb": "sk_skb_stream_verdict", "sk_msg": "sk_msg_verdict"}

// allowOnlyHooks are the hooks whose only verdict is Allow (`cgroup:allow` in bpf-mlir's ProgramAttaches.def — the kernel limits the return value to 1).
var allowOnlyHooks = map[[2]string]bool{
	{"cgroup_sock_addr", "recvmsg4"}: true, {"cgroup_sock_addr", "recvmsg6"}: true,
	{"cgroup_sock_addr", "getpeername4"}: true, {"cgroup_sock_addr", "getpeername6"}: true,
	{"cgroup_sock_addr", "getsockname4"}: true, {"cgroup_sock_addr", "getsockname6"}: true,
}

// hookKinds maps a kind whose hook is written in the directive to its hook names.
var hookKinds = map[string][]string{
	"cgroup_sock":      {"sock_create", "sock_release", "post_bind4", "post_bind6"},
	"cgroup_sock_addr": {"bind4", "connect4", "sendmsg4", "recvmsg4", "getpeername4", "getsockname4", "bind6", "connect6", "sendmsg6", "recvmsg6", "getpeername6", "getsockname6"},
}

// ctxFieldOfMethod maps a field method name to (field, r / w).
var ctxFieldOfMethod = map[string][2]string{
	"Len": {"len", "r"}, "Family": {"family", "r"}, "Type": {"type", "r"}, "Protocol": {"protocol", "r"},
	"SrcIP4": {"src_ip4", "r"}, "SrcPort": {"src_port", "r"}, "UserIP4": {"user_ip4", "r"}, "UserPort": {"user_port", "r"},
	"Op": {"op", "r"}, "RemotePort": {"remote_port", "r"}, "LocalPort": {"local_port", "r"},
	"Size": {"size", "r"}, "RemoteIP4": {"remote_ip4", "r"}, "LocalIP4": {"local_ip4", "r"}, // sk_msg
	"AccessType": {"access_type", "r"}, "Major": {"major", "r"}, "Minor": {"minor", "r"}, // cgroup_device
	"Write": {"write", "r"}, "FilePos": {"file_pos", "r"}, "SetFilePos": {"file_pos", "w"}, // cgroup_sysctl
	"Level": {"level", "r"}, "Optname": {"optname", "r"}, "Optlen": {"optlen", "r"}, "SetOptlen": {"optlen", "w"}, // cgroup_sockopt
	"EthProtocol": {"eth_protocol", "r"}, "IPProtocol": {"ip_protocol", "r"}, "BindInany": {"bind_inany", "r"}, "Hash": {"hash", "r"}, // sk_reuseport
	"SetMark": {"mark", "w"}, "SetUserIP4": {"user_ip4", "w"}, "SetUserPort": {"user_port", "w"}, "SetReply": {"reply", "w"},
	"Mark": {"mark", "r"}, "Priority": {"priority", "r"}, "SetPriority": {"priority", "w"}, "Ifindex": {"ifindex", "r"}, // lwt_seg6local
}

// ctxFieldSigned are the field methods whose value is a signed i32 (Go's int32) (level / optname / optlen of bpf_sockopt are int,
// and optlen can be written as −1). Other field methods are uint32.
var ctxFieldSigned = map[string]bool{"Level": true, "Optname": true, "Optlen": true, "SetOptlen": true}

// ctxFieldBits is the width of each (kind, field) that is not 32 bits (remote_port of bpf_sk_lookup is a 2-byte __be16, width 2 in bpf-mlir's
// ctxaccess.tsv — Go's uint16; remote_port of sk_msg stays 4 bytes — so it is keyed by kind and field, not by method name). Others are 32.
var ctxFieldBits = map[[2]string]int{{"sk_lookup", "remote_port"}: 16}

// ctxFieldWidth returns the width (bits) of a field of a kind's program.
func ctxFieldWidth(kind, field string) int {
	if b, ok := ctxFieldBits[[2]string{kind, field}]; ok {
		return b
	}
	return 32
}

// ctxAccessOK reports whether a program of kind and attach may use field in mode.
func ctxAccessOK(kind, attach, field, mode string) bool {
	ha, ok := hookAttach[[2]string{kind, attach}]
	if isSockmapProgKind(kind) {
		ha, ok = sockmapAttach[kind], true // the attach is the map name; the table's attach is decided by kind
	}
	if !ok {
		return false
	}
	for _, r := range ctxAccessRows {
		if r.kind == kind && r.attach == ha && r.field == field && r.mode == mode {
			return true
		}
	}
	return false
}

// ctxFieldsFor lists the fields a program of kind and attach may use in mode (for diagnostics).
func ctxFieldsFor(kind, attach, mode string) string {
	var out []string
	ha := hookAttach[[2]string{kind, attach}]
	if isSockmapProgKind(kind) {
		ha = sockmapAttach[kind]
	}
	for _, r := range ctxAccessRows {
		if r.kind == kind && r.attach == ha && r.mode == mode {
			out = append(out, r.field)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

// ctxFieldCall returns (field, mode) if call is a context field method call (`ctx.UserPort()`, `ctx.SetMark(v)`).
func (l *lowerer) ctxFieldCall(call *ast.CallExpr) (*ast.SelectorExpr, string, string, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || l.callOp(call) != "ctx_field" {
		return nil, "", "", false
	}
	fm := ctxFieldOfMethod[sel.Sel.Name]
	return sel, fm[0], fm[1], true
}

// ctxFieldPlace checks that a ctx field method is called on the program's context in the program body and is in the hook table (otherwise it reports and returns false).
func (l *lowerer) ctxFieldPlace(call *ast.CallExpr, sel *ast.SelectorExpr, field, mode string) bool {
	if l.progKind == nil || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.%s may only be called in the body of the program (a subprogram cannot take a socket or cgroup context)", sel.Sel.Name)
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.%s must be called on the program's context parameter", sel.Sel.Name)
		return false
	}
	k, at := l.progKind.Kind, l.prog.Attach
	if !ctxAccessOK(k, at, field, mode) {
		hook := at
		if hook == "" {
			hook = k
		}
		what := map[string]string{"r": "read", "w": "written"}[mode]
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "the %s field %s cannot be %s in a %s program at the %s hook (the kernel allows %s there: %s — bpf-mlir abi/ctxaccess.tsv)", k, field, what, k, hook, map[string]string{"r": "reading", "w": "writing"}[mode], ctxFieldsFor(k, at, mode))
		return false
	}
	return true
}

// ctxFieldRead lowers a read method to `ebpf.ctx.field %ctx "<field>" : !ebpf.ctx<"<kind>"> -> i32`.
func (l *lowerer) ctxFieldRead(call *ast.CallExpr) (value, bool, bool) {
	sel, field, mode, ok := l.ctxFieldCall(call)
	if !ok {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	if mode != "r" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.%s is a statement (it returns nothing)", sel.Sel.Name)
		return value{}, false, true
	}
	if !l.ctxFieldPlace(call, sel, field, mode) {
		return value{}, false, true
	}
	r := l.val()
	bits := ctxFieldWidth(l.progKind.Kind, field)
	l.emit("%s = ebpf.ctx.field %%ctx %q : !ebpf.ctx<%q> -> i%d", r, field, l.progKind.Kind, bits)
	return value{r, vtype{bits: bits, signed: ctxFieldSigned[sel.Sel.Name]}}, true, true
}

// ctxFieldWrite lowers a write method statement to `ebpf.ctx.field.store %ctx "<field>", %v : !ebpf.ctx<"<kind>">, i32` (handled is false for other statements).
func (l *lowerer) ctxFieldWrite(call *ast.CallExpr) bool {
	sel, field, mode, ok := l.ctxFieldCall(call)
	if !ok {
		return false
	}
	defer l.at(call.Pos())()
	if mode != "w" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "the value of ctx.%s is discarded — use it", sel.Sel.Name)
		return true
	}
	if !l.ctxFieldPlace(call, sel, field, mode) {
		return true
	}
	t := vtype{bits: 32, signed: ctxFieldSigned[sel.Sel.Name]}
	v, ok := l.expr(call.Args[0], &t)
	if !ok {
		return true
	}
	l.emit("ebpf.ctx.field.store %%ctx %q, %s : !ebpf.ctx<%q>, i32", field, v.name, l.progKind.Kind)
	return true
}
