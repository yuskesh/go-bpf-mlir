<!-- Generated — do not edit by hand. -->

# Program kinds

Target: bpf-mlir `v1.22.0` (commit 2bf11230). The tables follow what the ebpf-compile of this version accepts and rejects.

The context type of the first parameter decides the program kind (the table in `internal/frontend/ctxkind.go`). The verdict is the constant of the program's last `return` (value → bpf-mlir's verdict spelling). The capabilities a non-root loader needs are in the table of [docs/nonroot.md](../nonroot.md) (one row per kind).

| Context type | bpf-mlir kind | Attach | Verdict type | Verdict values | Attach API | Directive |
|---|---|---|---|---|---|---|
| `*bpf.XDPContext` | xdp | — | `bpf.XDPAction` | 0 = aborted, 1 = drop, 2 = pass, 3 = tx | `gobpf.AttachXDP(objs, Prog, ifindex)` | — |
| `*bpf.TCIngressContext` | sched_cls | ingress | `bpf.TCAction` | 0 = pass, 2 = drop | `gobpf.AttachTCX(objs, Prog, ifindex) — the direction is the context type` | — |
| `*bpf.TCEgressContext` | sched_cls | egress | `bpf.TCAction` | 0 = pass, 2 = drop | `gobpf.AttachTCX(objs, Prog, ifindex) — the direction is the context type` | — |
| `*bpf.FentryContext` | fentry | — | — | — (no result — done) | `gobpf.AttachFentry(objs, Prog)` | `//gobpf:fentry <kernel function>` |
| `*bpf.FexitContext[R]` | fexit | — | — | — (no result — done) | `gobpf.AttachFexit(objs, Prog)` | `//gobpf:fexit <kernel function> nargs=<0..12>` (the return type is the R of FexitContext[R]) |
| `*bpf.KprobeContext` | kprobe | — | — | — (no result — done) | `` | — |
| `*bpf.UprobeContext` | uprobe | — | — | — (no result — done) | `` | — |
| `*bpf.TPBTFContext` | tp_btf | — | — | — (no result — done) | `` | — |
| `*bpf.TracepointContext[E]` | tracepoint | — | — | — (no result — done) | `gobpf.AttachTracepoint(objs, Prog)` | `//gobpf:tracepoint <category>/<event>` |
| `*bpf.RawTPContext` | raw_tp | — | — | — (no result — done) | `gobpf.AttachRawTP(objs, Prog)` | `//gobpf:raw_tp <tracepoint>` |
| `*bpf.RawTPWritableContext` | raw_tp_writable | — | — | — (no result — done) | `gobpf.AttachRawTP(objs, Prog)` | — |
| `*bpf.KretprobeContext[R]` | kretprobe | — | — | — (no result — done) | `gobpf.AttachKretprobe(objs, Prog)` | `//gobpf:kretprobe <kernel function>` |
| `*bpf.UretprobeContext[R]` | uretprobe | — | — | — (no result — done) | `gobpf.AttachUretprobe(objs, Prog, target)` | `//gobpf:uretprobe <binary path> <symbol>` |
| `*bpf.SocketFilterContext` | socket_filter | — | `bpf.SocketFilterAction` | -1 = keep, 0 = drop | `gobpf.AttachSocketFilter(objs, Prog, fd)` | — |
| `*bpf.CgroupSKBIngressContext` | cgroup_skb | ingress | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupSKBEgressContext` | cgroup_skb | egress | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupSockContext` | cgroup_sock | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | `//gobpf:cgroup_sock <sock_create\|sock_release\|post_bind4\|post_bind6>` |
| `*bpf.SockAddrContext` | cgroup_sock_addr | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | `//gobpf:cgroup_sock_addr <bind4\|connect4\|sendmsg4\|recvmsg4\|getpeername4\|getsockname4\|bind6\|connect6\|sendmsg6\|recvmsg6\|getpeername6\|getsockname6>` |
| `*bpf.SockOpsContext` | sock_ops | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupDeviceContext` | cgroup_device | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupSetsockoptContext` | cgroup_sockopt | setsockopt | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupGetsockoptContext` | cgroup_sockopt | getsockopt | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.CgroupSysctlContext` | cgroup_sysctl | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.LSMContext` | lsm | — | `bpf.LSMRet` |  | `` | — |
| `*bpf.LSMSleepableContext` | lsm_s | — | `bpf.LSMRet` |  | `` | — |
| `*bpf.LSMCgroupContext` | lsm_cgroup | — | `bpf.CgroupAction` | 0 = deny, 1 = allow | `gobpf.AttachCgroup(objs, Prog, cgroupDir) — the attach type follows the kind and the hook` | — |
| `*bpf.PerfEventContext` | perf_event | — | — | — (no result — done) | `` | — |
| `*bpf.FsessionContext` | fsession | — | — | — (no result — done) | `gobpf.AttachFentry(objs, Prog)` | — |
| `*bpf.FmodRetContext` | fmod_ret | — | `bpf.FmodRet` |  | `gobpf.AttachFentry(objs, Prog)` | — |
| `*bpf.SyscallContext` | syscall | — | `bpf.SyscallRet` |  | `` | — |
| `*bpf.ExtContext` | ext | — | the result type of the replaced function | — (a computed value) | `gobpf.AttachExt(objs, Prog) — the replaced function is in a program of the same Load` | `//gobpf:ext <program> <global function>` |
| `*bpf.StructOpsContext` | struct_ops | — | per the member table (none, uint32) | — (done or a computed value) | `gobpf.AttachStructOps(objs, &Map) — the registration is a system-wide name` | `//gobpf:struct_ops <struct_ops map> <member>` |
| `*bpf.KprobeSessionContext` | kprobe_session | — | `bpf.KprobeSessionRet` |  | `` | — |
| `*bpf.IterContext` | iter | — | — | — (no result — done) | `` | — |
| `*bpf.KsyscallContext` | ksyscall | — | — | — (no result — done) | `` | — |
| `*bpf.KprobeContext` | kprobe_multi | — | — | — (no result — done) | `` | — |
| `*bpf.KretprobeContext` | kretprobe_multi | — | — | — (no result — done) | `` | — |
| `*bpf.UprobeContext` | uprobe_multi | — | — | — (no result — done) | `` | — |
| `*bpf.UretprobeContext` | uretprobe_multi | — | — | — (no result — done) | `` | — |
| `*bpf.USDTContext` | usdt | — | — | — (no result — done) | `` | — |
| `*bpf.SKSKBContext` | sk_skb | — | `bpf.SKAction` | 0 = drop, 1 = pass | `` | — |
| `*bpf.LWTInContext` | lwt_in | — | `bpf.LWTAction` | 0 = ok, 2 = drop | `` | — |
| `*bpf.LWTOutContext` | lwt_out | — | `bpf.LWTAction` | 0 = ok, 2 = drop | `` | — |
| `*bpf.LWTXmitContext` | lwt_xmit | — | `bpf.LWTAction` | 0 = ok, 2 = drop | `` | — |
| `*bpf.Seg6LocalContext` | lwt_seg6local | — | `bpf.Seg6Action` | 0 = ok, 2 = drop | `` | — |
| `*bpf.NetfilterContext` | netfilter | — | `bpf.NFAction` | 0 = drop, 1 = accept | `` | — |
| `*bpf.FlowDissectorContext` | flow_dissector | — | `bpf.FlowAction` | 0 = ok, 2 = drop, 129 = flow_dissector_continue | `` | — |
| `*bpf.SkReuseportContext` | sk_reuseport | — | `bpf.SKAction` | 0 = drop, 1 = pass | `gobpf.AttachSocketFilter(objs, Prog, fd)` | — |
| `*bpf.SkLookupContext` | sk_lookup | — | `bpf.SKAction` | 0 = drop, 1 = pass | `` | — |
| `*bpf.SKMsgContext` | sk_msg | — | `bpf.SKAction` | 0 = drop, 1 = pass | `` | — |
| `*bpf.TCActContext` | sched_act | — | `bpf.TCActAction` | 0 = ok, 2 = shot, 3 = pipe | `` | — |

## Capabilities each kind provides

A function reachable from a program that uses a construct whose capability the kind does not provide is GB011 (with the path).

| Kind | Capabilities |
|---|---|
| cgroup_device | `arith`, `bpf.call`, `bpf.map` |
| cgroup_skb | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| cgroup_sock | `arith`, `bpf.call`, `bpf.map` |
| cgroup_sock_addr | `arith`, `bpf.call`, `bpf.map` |
| cgroup_sockopt | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| cgroup_sysctl | `arith`, `bpf.call`, `bpf.map` |
| ext | `arith`, `bpf.call`, `bpf.map` |
| fentry | `arith`, `bpf.call`, `bpf.map` |
| fexit | `arith`, `bpf.call`, `bpf.map` |
| flow_dissector | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| fmod_ret | `arith`, `bpf.call`, `bpf.map` |
| fsession | `arith`, `bpf.call`, `bpf.map` |
| iter | `arith`, `bpf.call`, `bpf.map` |
| kprobe | `arith`, `bpf.call`, `bpf.map` |
| kprobe_multi | `arith`, `bpf.call`, `bpf.map` |
| kprobe_session | `arith`, `bpf.call`, `bpf.map` |
| kretprobe | `arith`, `bpf.call`, `bpf.map` |
| kretprobe_multi | `arith`, `bpf.call`, `bpf.map` |
| ksyscall | `arith`, `bpf.call`, `bpf.map` |
| lsm | `arith`, `bpf.call`, `bpf.map` |
| lsm_cgroup | `arith`, `bpf.call`, `bpf.map` |
| lsm_s | `arith`, `bpf.call`, `bpf.map` |
| lwt_in | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| lwt_out | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| lwt_seg6local | `arith`, `bpf.call`, `bpf.map` |
| lwt_xmit | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| netfilter | `arith`, `bpf.call`, `bpf.map` |
| perf_event | `arith`, `bpf.call`, `bpf.map` |
| raw_tp | `arith`, `bpf.call`, `bpf.map` |
| raw_tp_writable | `arith`, `bpf.call`, `bpf.map` |
| sched_act | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| sched_cls | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |
| sk_lookup | `arith`, `bpf.call`, `bpf.map` |
| sk_msg | `arith`, `bpf.call`, `bpf.map` |
| sk_reuseport | `arith`, `bpf.call`, `bpf.map` |
| sk_skb | `arith`, `bpf.call`, `bpf.map` |
| sock_ops | `arith`, `bpf.call`, `bpf.map` |
| socket_filter | `arith`, `bpf.call`, `bpf.map` |
| struct_ops | `arith`, `bpf.call`, `bpf.map` |
| syscall | `arith`, `bpf.call`, `bpf.map` |
| tp_btf | `arith`, `bpf.call`, `bpf.map` |
| tracepoint | `arith`, `bpf.call`, `bpf.map` |
| uprobe | `arith`, `bpf.call`, `bpf.map` |
| uprobe_multi | `arith`, `bpf.call`, `bpf.map` |
| uretprobe | `arith`, `bpf.call`, `bpf.map` |
| uretprobe_multi | `arith`, `bpf.call`, `bpf.map` |
| usdt | `arith`, `bpf.call`, `bpf.map` |
| xdp | `arith`, `bpf.call`, `bpf.map`, `bpf.packet` |

## Capability names

| Capability | Meaning |
|---|---|
| `arith` | integer and bool arithmetic |
| `bpf.call` | calls to subprograms of the same package |
| `bpf.map` | map operations (Lookup / Update / AtomicAdd / Output / TailCall …) |
| `bpf.packet` | packet reads and writes (ctx.Check and Window) |
| `go.chan` | channel operations |
| `go.defer` | defer |
| `go.float` | floating point |
| `go.goroutine` | go statements |
| `go.heap` | heap allocation (taking an address with &, composite literals, new / make / append) |
| `go.interface` | dynamic interface calls |
| `go.map` | Go maps |
| `go.panic` | panic / recover |
| `go.runtime` | calls to Go runtime functions |
| `go.slice` | slice |
| `go.string` | string |
| `go.unbounded_loop` | loops not in a bounded form |
| `unknown` | constructs not in the capability table (fail closed) |
