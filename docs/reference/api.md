<!-- Generated — do not edit by hand. -->

# API — bpf and gobpf identifiers

Target: bpf-mlir `v1.20.0` (commit d3e13842). The tables follow what the ebpf-compile of this version accepts and rejects.

The bpf identifiers the frontend accepts (apiTable in `internal/frontend/table.go` — a bpf / gobpf identifier not in the table stops with GB002). Using one outside its "Side" is GB003. Lowering is the bpf-mlir ops emitted on the eBPF side. The description is the first sentence of the bpf doc comment.

## (functions and constants)

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.AtomicAdd` | eBPF side | `ebpf.ref.field.atomic_add` | AtomicAdd is eBPF side only: adds delta to a record field **atomically** (no result — the value before the add is not returned). |
| `bpf.CgroupAction` | both | — | CgroupAction is the verdict of cgroup-family programs (the kernel verifier limits the return value to 0..1). |
| `bpf.CgroupAllow` | both | `ebpf.verdict` | cgroup-family verdicts (CgroupDeny makes connect() and similar calls fail with EPERM and drops cgroup_skb packets; CgroupAllow allows). |
| `bpf.CgroupDeny` | both | `ebpf.verdict` | cgroup-family verdicts (CgroupDeny makes connect() and similar calls fail with EPERM and drops cgroup_skb packets; CgroupAllow allows). |
| `bpf.ConfigInt` | both | — | ConfigInt is the value type of Config (an integer of 8 to 64 bits). |
| `bpf.CountDropsIn` | eBPF side | `ebpf.map.atomic_add` | CountDropsIn is eBPF side only: write it only in the position of Output's second argument (`Events.Output(v, bpf.CountDropsIn(Drops, 0))`). |
| `bpf.Create` | both | — | Constants for how Get creates (write them as constants — the frontend stops expressions). |
| `bpf.CurrentComm` | eBPF side | `ebpf.task.comm` | CurrentComm is eBPF side only: the current task's name (helper get_current_comm — 16 bytes, NUL-padded). |
| `bpf.CurrentPidTgid` | eBPF side | `ebpf.task.pid_tgid` | CurrentPidTgid is eBPF side only: the current task's tgid << 32 \| pid (helper get_current_pid_tgid). |
| `bpf.DropCounter` | both | — | DropCounter is where Output counts dropped events (made by CountDropsIn — not passed around as a value). |
| `bpf.E2BIG` | both | — | errno constants — Linux errno values (the absolute values of BPF helpers' negative returns). |
| `bpf.EEXIST` | both | — | errno constants — Linux errno values (the absolute values of BPF helpers' negative returns). |
| `bpf.ENOENT` | both | — | errno constants — Linux errno values (the absolute values of BPF helpers' negative returns). |
| `bpf.ENOMEM` | both | — | errno constants — Linux errno values (the absolute values of BPF helpers' negative returns). |
| `bpf.ExtArg` | eBPF side | `ebpf.ext.arg` | ExtArg is eBPF side only: the value of the replaced function's i-th (constant) argument (ebpf.ext.arg). |
| `bpf.ExtContext` | both | — | ExtContext is the context of an ext (BPF_PROG_TYPE_EXT, freplace) program. |
| `bpf.FentryArg` | eBPF side | `ebpf.ctx.arg`, `ebpf.kptr.check` | FentryArg is eBPF side only: returns argument i (a constant 0..11) of the fentry program's attached function as a pointer to the kernel's struct T (ebpf.ctx.arg — bpf-mlir's fentry arguments). |
| `bpf.FentryArgInt` | eBPF side | `ebpf.ctx.arg` | FentryArgInt is eBPF side only: the value of the fentry program's attached function's integer argument i (a constant 0..11) (ebpf.ctx.arg — from the 8-byte slot to T's width, bpf-mlir's integer fentry arguments). |
| `bpf.FentryContext` | both | — | FentryContext is the context of an fentry (tracing) program. |
| `bpf.FlowAction` | both | — | FlowAction is the flow_dissector verdict (the kernel's enum bpf_ret_code). |
| `bpf.FlowContinue` | both | `ebpf.verdict` | flow_dissector verdicts: FlowOK uses flow_keys as the flow key, FlowDrop is a dissect failure, and FlowContinue hands back to the kernel's dissector. |
| `bpf.FlowDrop` | both | `ebpf.verdict` | flow_dissector verdicts: FlowOK uses flow_keys as the flow key, FlowDrop is a dissect failure, and FlowContinue hands back to the kernel's dissector. |
| `bpf.FlowOK` | both | `ebpf.verdict` | flow_dissector verdicts: FlowOK uses flow_keys as the flow key, FlowDrop is a dissect failure, and FlowContinue hands back to the kernel's dissector. |
| `bpf.FmodRet` | both | — | FmodRet is the return value of an fmod_ret program (0 runs the original function; a nonzero value skips it and returns that value). |
| `bpf.FmodRetArgInt` | eBPF side | — | FmodRetArgInt is eBPF side only: the value of integer argument i (a constant 0..11) of the attached function (ebpf.ctx.arg — the same shape as FentryArgInt). |
| `bpf.FmodRetContext` | both | — | FmodRetContext is the context of an fmod_ret (BPF_MODIFY_RETURN) program. |
| `bpf.GlobalInt` | both | — | GlobalInt is the value type of Global (a 32 / 64-bit integer — the width of BPF atomic adds). |
| `bpf.InnerArray` | both | — | Inner map kinds (constants only). |
| `bpf.InnerHash` | both | — | Inner map kinds (constants only). |
| `bpf.InnerKind` | both | — | InnerKind is the kind of the inner map. |
| `bpf.InnerLRUHash` | both | — | Inner map kinds (constants only). |
| `bpf.Kernel` | both | — | Kernel is the marker of a local declaration of a kernel struct (size 0). |
| `bpf.KernelStr` | both | — | KernelStr is the type of a `char *` field of a kernel local-type struct (strptr of bpf-mlir's schema kernel_types). |
| `bpf.Key32` | both | — | Key32 is the key type of array maps. |
| `bpf.KprobeArg` | eBPF side | `ebpf.kprobe.arg` | KprobeArg is eBPF side only: reads the register of the kprobe function's argument n (a constant 1 to 6 — x86_64 register passing) as T. |
| `bpf.KprobeContext` | both | — | KprobeContext is the context of a kprobe program (struct pt_regs). |
| `bpf.KprobeInt` | both | — | KprobeInt is the type of KprobeArg (an integer of 8 to 64 bits). |
| `bpf.KprobeRead` | eBPF side | `ebpf.kprobe.arg`, `ebpf.kernel.read_scalar` | KprobeRead is eBPF side only: reads a fixed-width value at byte off (a constant 0 to 4095) behind the kprobe function's argument n (a constant 1 to 6 — **a pointer argument**) as T (an integer of 8 to 64 bits) (bpf-mlir's ebpf.kernel.read_scalar, helper probe_read_kernel). |
| `bpf.KprobeSessionRet` | both | — | KprobeSessionRet is the return value of a kprobe_session program (constants only — KprobeSessionRun or KprobeSessionSkipReturn). |
| `bpf.KprobeSessionRun` | both | `ebpf.verdict` | kprobe_session return values: KprobeSessionRun runs the return run, and KprobeSessionSkipReturn (returned from the entry run) skips the return run. |
| `bpf.KprobeSessionSkipReturn` | both | `ebpf.verdict` | kprobe_session return values: KprobeSessionRun runs the return run, and KprobeSessionSkipReturn (returned from the entry run) skips the return run. |
| `bpf.KprobeValue` | both | — | KprobeValue is the type of KprobeArg: an integer of 8 to 64 bits or uintptr (a pointer argument — a value that is not dereferenced). |
| `bpf.KsyscallArg` | eBPF side | `ebpf.ksyscall.arg` | KsyscallArg is eBPF side only: the value of syscall argument n (a constant 1..6). |
| `bpf.KsyscallContext` | both | — | KsyscallContext is the context of a ksyscall program (the wrapper's pt_regs). |
| `bpf.KtimeNs` | eBPF side | `ebpf.ktime.ns` | KtimeNs is eBPF side only: the monotonic clock in ns (helper ktime_get_ns). |
| `bpf.LPMKey4` | user space | — | LPMKey4 is the key layout of LPMTrie4 (the schema record gobpf_lpm_key4). |
| `bpf.LPMValue` | both | — | LPMValue is the value type of LPMTrie4 (a 32 / 64-bit integer — the same rule as integer values of the hash family). |
| `bpf.LSMAllow` | both | `ebpf.verdict` | LSMAllow allows the operation (0). |
| `bpf.LSMArg` | eBPF side | — | LSMArg is eBPF side only: returns argument i (a constant 0..11) of the lsm hook as a pointer to the kernel's struct T (ebpf.ctx.arg — the same shape as FentryArg). |
| `bpf.LSMArgInt` | eBPF side | — | LSMArgInt is eBPF side only: the value of the lsm hook's integer argument i (a constant 0..11) (ebpf.ctx.arg — the same shape as FentryArgInt). |
| `bpf.LSMCgroupContext` | both | — | LSMCgroupContext is the context of an lsm_cgroup (BPF_LSM_CGROUP) program (no methods). |
| `bpf.LSMContext` | both | — | LSMContext is the context of an lsm (BPF_LSM_MAC) program. |
| `bpf.LSMDeny` | both | — | LSMDeny rejects the operation with errno (−errno — for example LSMDeny(1) is −EPERM). |
| `bpf.LSMHook` | both | — | LSMHook is the context type of LSMArg / LSMArgInt (LSMContext or LSMSleepableContext). |
| `bpf.LSMRet` | both | — | LSMRet is the return value of an lsm program (0 allows; a negative value −4095..−1 rejects the operation with −errno). |
| `bpf.LSMSleepableContext` | both | — | LSMSleepableContext is the context of an lsm.s (sleepable lsm — BPF_F_SLEEPABLE) program. |
| `bpf.LWTAction` | both | — | LWTAction is the lwt verdict (the kernel's enum bpf_ret_code). |
| `bpf.LWTDrop` | both | `ebpf.verdict` | lwt verdicts: LWTOK goes to the route's next stage, and LWTDrop drops the packet (−EPERM). |
| `bpf.LWTOK` | both | `ebpf.verdict` | lwt verdicts: LWTOK goes to the route's next stage, and LWTDrop drops the packet (−EPERM). |
| `bpf.MultiProbeContext` | both | — | MultiProbeContext is a context that ProbeTargetIndex accepts (*KprobeContext, *KretprobeContext[R] — the context of a program of a multi kind). |
| `bpf.NFAccept` | both | `ebpf.verdict` | netfilter verdicts: NFDrop drops the packet (at LOCAL_OUT the send gets EPERM), NFAccept goes on to the next hook. |
| `bpf.NFAction` | both | — | NFAction is a netfilter verdict (the kernel's NF_DROP / NF_ACCEPT). |
| `bpf.NFDrop` | both | `ebpf.verdict` | netfilter verdicts: NFDrop drops the packet (at LOCAL_OUT the send gets EPERM), NFAccept goes on to the next hook. |
| `bpf.NoCreate` | both | — | Constants for how Get creates (write them as constants — the frontend stops expressions). |
| `bpf.ProbeTargetIndex` | eBPF side | `ebpf.probe.target_index` | ProbeTargetIndex is eBPF side only: the index in the list (0..N−1) of the function a multi-probe program is running for (the cookie the loader set, ebpf.probe.target_index). |
| `bpf.PushAny` | both | — | Push flags (PushAny does not insert when full and gives −E2BIG; PushExist drops the oldest element when full and inserts — the kernel's queue_stack_map_push_elem BPF_EXIST). |
| `bpf.PushExist` | both | — | Push flags (PushAny does not insert when full and gives −E2BIG; PushExist drops the oldest element when full and inserts — the kernel's queue_stack_map_push_elem BPF_EXIST). |
| `bpf.PushFlag` | both | — | PushFlag is the flags of Queue / Stack Push (BPF_ANY / BPF_EXIST — constants only). |
| `bpf.RawTPArg` | eBPF side | `ebpf.ctx.field` | RawTPArg is eBPF side only: the raw value of raw_tp argument i (a constant 0 to 11) (ebpf.ctx.field "args"[i]). |
| `bpf.RawTPContext` | both | — | RawTPContext is the context of a raw_tp (raw tracepoint — `//gobpf:raw_tp <tracepoint>`) program. |
| `bpf.RetInt` | both | — | RetInt is the return type R of kretprobe / uretprobe (a 32 / 64-bit integer). |
| `bpf.SKAction` | both | — | SKAction is the sk_skb verdict (the kernel's enum sk_action). |
| `bpf.SKDirection` | both | — | SKDirection is the redirect direction (whether BPF_F_INGRESS is set). |
| `bpf.SKDrop` | both | `ebpf.verdict` | sk_skb verdicts (the same values as the UAPI enum sk_action): SKDrop drops the skb, and SKPass goes to the receiving socket. |
| `bpf.SKEgress` | both | — | Redirect directions: SKEgress sends from the target socket, and SKIngress puts it into the target socket's receive path (BPF_F_INGRESS). |
| `bpf.SKIngress` | both | — | Redirect directions: SKEgress sends from the target socket, and SKIngress puts it into the target socket's receive path (BPF_F_INGRESS). |
| `bpf.SKPass` | both | `ebpf.verdict` | sk_skb verdicts (the same values as the UAPI enum sk_action): SKDrop drops the skb, and SKPass goes to the receiving socket. |
| `bpf.Seg6Action` | both | — | Seg6Action is the verdict of lwt_seg6local (the kernel's enum bpf_ret_code). |
| `bpf.Seg6Drop` | both | `ebpf.verdict` | lwt_seg6local verdicts: Seg6OK looks up and forwards to the next segment, and Seg6Drop drops the packet. |
| `bpf.Seg6OK` | both | `ebpf.verdict` | lwt_seg6local verdicts: Seg6OK looks up and forwards to the next segment, and Seg6Drop drops the packet. |
| `bpf.SkAssignFlags` | both | — | SkAssignFlags is the flags of Assign (sklookupflag in bpf-mlir's UAPI table — constants only, combinable with `\|`). |
| `bpf.SkAssignNoReuseport` | both | — | Assign flags: SkAssignReplace replaces the socket chosen by a previous program (or a previous Assign of the same program) (−EEXIST without it), and SkAssignNoReuseport skips reselection within the chosen socket's reuseport group. |
| `bpf.SkAssignReplace` | both | — | Assign flags: SkAssignReplace replaces the socket chosen by a previous program (or a previous Assign of the same program) (−EEXIST without it), and SkAssignNoReuseport skips reselection within the chosen socket's reuseport group. |
| `bpf.Slot` | user space | — | Slot is the result of TailSlot (the value has no meaning — discard it with `var _ =`). |
| `bpf.SockAny` | both | — | Insert flags: SockAny inserts whether or not the key exists, SockNoExist only for a missing key (−EEXIST if present), SockExist only for an existing key. |
| `bpf.SockExist` | both | — | Insert flags: SockAny inserts whether or not the key exists, SockNoExist only for a missing key (−EEXIST if present), SockExist only for an existing key. |
| `bpf.SockFlags` | both | — | SockFlags is the flags of Insert (BPF_ANY / BPF_NOEXIST / BPF_EXIST). |
| `bpf.SockNoExist` | both | — | Insert flags: SockAny inserts whether or not the key exists, SockNoExist only for a missing key (−EEXIST if present), SockExist only for an existing key. |
| `bpf.SocketDrop` | both | `ebpf.verdict` | socket_filter verdicts (SocketDrop drops the packet, SocketKeep accepts all bytes — the u32 maximum). |
| `bpf.SocketFilterAction` | both | — | SocketFilterAction is the verdict of a socket_filter program (the kernel's sk_filter_trim_cap — 0 drops, the u32 maximum accepts all bytes). |
| `bpf.SocketKeep` | both | `ebpf.verdict` | socket_filter verdicts (SocketDrop drops the packet, SocketKeep accepts all bytes — the u32 maximum). |
| `bpf.SpinLock` | both | — | SpinLock is a record field type (struct bpf_spin_lock — 4 bytes). |
| `bpf.StackBuildIDEntry` | user space | — | StackBuildIDEntry is the bytes of one element of a build id stack (32 bytes — the schema's stack_build_id, used to check gobpf's map declaration). |
| `bpf.StackContext` | both | — | StackContext is the marker of program contexts that can take the user stack (*FentryContext, *KprobeContext, *UprobeContext). |
| `bpf.StackDepth` | user space | — | StackDepth is the depth of an IP stack (the number of elements before the first 0 — bindrt.StackDepth). |
| `bpf.StackFrame` | user space | — | StackFrame is one element of a build id stack (bindrt.StackBuildIDFrame — read by the rules of bindrt.DecodeStackBuildID as is). |
| `bpf.StackFrameEmpty` | user space | — | Per-element status values (the same as the bindrt constants). |
| `bpf.StackFrameIP` | user space | — | Per-element status values (the same as the bindrt constants). |
| `bpf.StackFrameStatus` | user space | — | StackFrameStatus is the type of StackFrame.Status (bindrt.StackFrameStatus — the values are the UAPI enum bpf_stack_build_id_status; an alias). |
| `bpf.StackFrameValid` | user space | — | Per-element status values (the same as the bindrt constants). |
| `bpf.StorageFlag` | both | — | StorageFlag is how Get creates (bpf.Create creates as 0 if missing, bpf.NoCreate gives nil if missing). |
| `bpf.StructOpsArg` | eBPF side | `ebpf.ctx.arg`, `ebpf.kptr.check` | StructOpsArg is eBPF side only: returns the member's struct argument i (for tcp_congestion_ops members, i = 0 is `struct sock *` — the verifier promotes it to tcp_sock, so T is a local type with tag `kernel:"tcp_sock"`) as a pointer to the kernel's struct T (ebpf.ctx.arg). |
| `bpf.StructOpsArgInt` | eBPF side | `ebpf.ctx.arg` | StructOpsArgInt is eBPF side only: the value of the member's integer argument i (ebpf.ctx.arg — cong_avoid's 1 = ack, 2 = acked; T is uint32). |
| `bpf.StructOpsContext` | both | — | StructOpsContext is the context of a struct_ops program (the member's arguments — StructOpsArg / StructOpsArgInt). |
| `bpf.SumPerCPU` | user space | — | SumPerCPU is the sum of integer per-CPU values (for the result of GetPerCPU). |
| `bpf.SysBpf` | eBPF side | `ebpf.record.make`, `ebpf.sys.bpf` | SysBpf is eBPF side only (a top-level statement of a syscall program body, `st := bpf.SysBpf(ctx, cmd, attr)` — bpf-mlir's ebpf.sys.bpf): calls bpf(cmd, &attr, sizeof attr) from inside the kernel with helper bpf_sys_bpf and returns the raw status (map_create / map_get_fd_by_id give a new fd — it goes into **the fd table of the process that called the test run**, and the caller closes it; map_freeze gives 0; failure gives a negative errno). |
| `bpf.SysBpfCmd` | both | — | SysBpfCmd is the cmd of SysBpf (the same values as the UAPI enum bpf_cmd — only the 3 whose attr has no pointer fields). |
| `bpf.SysBpfMapCreate` | both | — | SysBpf cmds: SysBpfMapCreate (BPF_MAP_CREATE), SysBpfMapGetFdByID (BPF_MAP_GET_FD_BY_ID — −EPERM for a loader without CAP_SYS_ADMIN), SysBpfMapFreeze (BPF_MAP_FREEZE — a second freeze of a frozen map gives −EPERM). |
| `bpf.SysBpfMapFreeze` | both | — | SysBpf cmds: SysBpfMapCreate (BPF_MAP_CREATE), SysBpfMapGetFdByID (BPF_MAP_GET_FD_BY_ID — −EPERM for a loader without CAP_SYS_ADMIN), SysBpfMapFreeze (BPF_MAP_FREEZE — a second freeze of a frozen map gives −EPERM). |
| `bpf.SysBpfMapGetFdByID` | both | — | SysBpf cmds: SysBpfMapCreate (BPF_MAP_CREATE), SysBpfMapGetFdByID (BPF_MAP_GET_FD_BY_ID — −EPERM for a loader without CAP_SYS_ADMIN), SysBpfMapFreeze (BPF_MAP_FREEZE — a second freeze of a frozen map gives −EPERM). |
| `bpf.SysClose` | eBPF side | `ebpf.sys.close` | SysClose is eBPF side only (a top-level statement of a syscall program body): closes fd in the fd table of the process that called the test run with helper bpf_sys_close, and returns the raw status (0; −EBADF for a missing fd). |
| `bpf.SyscallContext` | both | — | SyscallContext is the context of a syscall (BPF_PROG_TYPE_SYSCALL) program (the user's byte slice). |
| `bpf.SyscallLoad` | eBPF side | `ebpf.ctx.load` | SyscallLoad is eBPF side only: reads T (an integer of 8 to 64 bits, little endian) at off of the ctx byte slice (ebpf.ctx.load). |
| `bpf.SyscallRet` | both | — | SyscallRet is the return value of a syscall program (the test run's retval — passed to the user as a u32). |
| `bpf.TCActAction` | both | — | TCActAction is a sched_act verdict (tc's TC_ACT_* — pkt_cls.h). |
| `bpf.TCActOK` | both | `ebpf.verdict` | sched_act verdicts (a subset of tc_act): TCActOK passes the packet, TCActShot drops it (adding to the act's drop count), TCActPipe goes on to the next action. |
| `bpf.TCActPipe` | both | `ebpf.verdict` | sched_act verdicts (a subset of tc_act): TCActOK passes the packet, TCActShot drops it (adding to the act's drop count), TCActPipe goes on to the next action. |
| `bpf.TCActShot` | both | `ebpf.verdict` | sched_act verdicts (a subset of tc_act): TCActOK passes the packet, TCActShot drops it (adding to the act's drop count), TCActPipe goes on to the next action. |
| `bpf.TCAction` | both | — | TCAction is the verdict of a sched_cls program (values of the UAPI tcx_action_base). |
| `bpf.TCContext` | both | — | TCContext is the context of a tc (sched_cls) program (TCIngressContext, TCEgressContext — the ctx that SkbUnder accepts). |
| `bpf.TCDrop` | both | `ebpf.verdict` | sched_cls verdicts. |
| `bpf.TCPass` | both | `ebpf.verdict` | sched_cls verdicts. |
| `bpf.TPArg` | eBPF side | `ebpf.ctx.arg`, `ebpf.kptr.check` | TPArg is eBPF side only: returns argument i (a constant 0..11) of the tp_btf tracepoint as a pointer to the kernel's struct T (ebpf.ctx.arg). |
| `bpf.TPArgInt` | eBPF side | `ebpf.ctx.arg` | TPArgInt is eBPF side only: the value of the tp_btf tracepoint's integer argument i (a constant 0..11) (ebpf.ctx.arg). |
| `bpf.TPBTFContext` | both | — | TPBTFContext is the context of a tp_btf (raw tracepoint with BTF types) program. |
| `bpf.TailSlot` | user space | — | TailSlot is a prog_array slot declaration: puts xdp program prog in m's slot. |
| `bpf.USDTArg` | eBPF side | `ebpf.usdt.arg` | USDTArg is eBPF side only: reads argument n (a constant 1..12) of the USDT point now running as T, and returns the value and the raw status (0 is success; −ENOENT if the point has no spec; a failed read of a memory location gives probe_read_user's value; on failure the value is 0). |
| `bpf.USDTContext` | both | — | USDTContext is the context of a usdt program (struct pt_regs). |
| `bpf.UprobeArg` | eBPF side | `ebpf.uprobe.arg` | UprobeArg is eBPF side only: reads argument n (a constant 1 to 6 — SysV register passing) of the user function as T (the same rules as KprobeArg — T is in the schema's params, and if it differs from the binary's DWARF type, generate and gobpf.Load stop. |
| `bpf.UprobeContext` | both | — | UprobeContext is the context of a uprobe program (struct pt_regs). |
| `bpf.UprobeStr` | eBPF side | `ebpf.uprobe.arg` | UprobeStr is eBPF side only: argument n as a pointer to a user string (if the DWARF type is not a single-level pointer to an 8-bit char — const char * — generate and gobpf.Load stop). |
| `bpf.UserStr` | both | — | UserStr is a pointer to a user string (a uprobe argument — bpf-mlir's !ebpf.user_str). |
| `bpf.WithLock` | eBPF side | `ebpf.spin.region` | WithLock is eBPF side only: a closed critical region that takes lock, runs f, and releases it (bpf-mlir's ebpf.spin.region — forgetting to unlock cannot happen by construction). |
| `bpf.XDPAborted` | both | `ebpf.verdict` | xdp verdicts (the same values as the UAPI enum xdp_action). |
| `bpf.XDPAction` | both | — | XDPAction is the verdict of an xdp program. |
| `bpf.XDPDrop` | both | `ebpf.verdict` | xdp verdicts (the same values as the UAPI enum xdp_action). |
| `bpf.XDPPass` | both | `ebpf.verdict` | xdp verdicts (the same values as the UAPI enum xdp_action). |
| `bpf.XDPTx` | both | `ebpf.verdict` | xdp verdicts (the same values as the UAPI enum xdp_action). |

## Array

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Array` | both | — | Array is the declaration of a BPF_MAP_TYPE_ARRAY map. |
| `bpf.Array.AtomicAdd` | eBPF side | `ebpf.map.atomic_add` | AtomicAdd is eBPF side only: atomically adds d to the key's value (does nothing if there is no element). |
| `bpf.Array.Get` | user space | — | Get is user-space side only: reads the key's value from the loaded map. |
| `bpf.Array.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime: the spelling of the map kind (checked against the type of the map row in the ELF's requirements — stops before load a build that changed only the map kind after generation (PerCPUArray → Array, etc.)). |
| `bpf.Array.GobpfTypes` | user space | — | GobpfTypes is **an internal API of the gobpf runtime** (user code does not call it — hence the Gobpf name prefix): the Go types of the map's key and value. |
| `bpf.Array.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: a pointer to the key's value (nil if none). |
| `bpf.Array.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.Array.Put` | user space | — | Put is user-space side only: sets the key's value in the loaded map to v. |
| `bpf.Array.Update` | eBPF side | `ebpf.map.update` | Update is eBPF side only: sets the key's value to v. |

## ArrayOfMaps

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.ArrayOfMaps` | both | — | ArrayOfMaps is the declaration of a BPF_MAP_TYPE_ARRAY_OF_MAPS (the outer key is a u32 index). |
| `bpf.ArrayOfMaps.GobpfInner` | user space | — | GobpfInner is an internal API of the gobpf runtime: the inner template's kind, key and value types, and max_entries (Inner of bindrt's MapDecl). |
| `bpf.ArrayOfMaps.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.ArrayOfMaps.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the outer key and value (a u32 inner map fd). |
| `bpf.ArrayOfMaps.Inner` | user space | — | Inner is the inner map's template. |
| `bpf.ArrayOfMaps.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.map.inner` | Lookup is eBPF side only: the inner map in outer slot k (nil if none). |
| `bpf.ArrayOfMaps.MaxEntries` | user space | — | MaxEntries is the number of outer slots (a nonzero constant). |
| `bpf.ArrayOfMaps.NewInner` | user space | — | NewInner is user space only: creates a new inner map of the template's shape (Inner and the type arguments) (after the outer Load — insert it into the outer map with Set). |
| `bpf.ArrayOfMaps.Remove` | user space | — | Remove is user space only: empties outer slot k. |
| `bpf.ArrayOfMaps.Set` | user space | — | Set is user space only: inserts the inner map into outer slot k (the previous inner map leaves the outer map — the user's handle stays valid until Close). |

## BloomFilter

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.BloomFilter` | both | — | BloomFilter is the declaration of a BPF_MAP_TYPE_BLOOM_FILTER (a probabilistic set — false positives are possible, false negatives are not). |
| `bpf.BloomFilter.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime: the bloom flags (BPF_F_ZERO_SEED = 64 if ZeroSeed). |
| `bpf.BloomFilter.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.BloomFilter.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Queue.GobpfTypes). |
| `bpf.BloomFilter.Has` | user space | — | Has is user space only: true if v may be present (false positives are possible), false if not. |
| `bpf.BloomFilter.MaxEntries` | user space | — | MaxEntries is the expected number of elements (a nonzero constant). |
| `bpf.BloomFilter.Peek` | eBPF side | `ebpf.bloom.peek` | Peek is eBPF side only: 0 if v may be present, −ENOENT if not (0 can be a false positive). |
| `bpf.BloomFilter.Push` | eBPF side | `ebpf.map.push` | Push is eBPF side only: inserts v into the set (flags are any only). |
| `bpf.BloomFilter.Put` | user space | — | Put is user space only: inserts v into the set. |
| `bpf.BloomFilter.ZeroSeed` | user space | — | ZeroSeed sets the hash seed to 0 (BPF_F_ZERO_SEED — a constant; false positives become the same on every run). |

## CPUMap

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CPUMap` | both | — | CPUMap is the declaration of a BPF_MAP_TYPE_CPUMAP: the key is a CPU number, and the value is the size of the queue on that CPU (qsize). |
| `bpf.CPUMap.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.CPUMap.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key and value are u32. |
| `bpf.CPUMap.MaxEntries` | user space | — | MaxEntries is the maximum number of CPUs (a nonzero constant — at most the number of possible CPUs). |
| `bpf.CPUMap.Redirect` | eBPF side | `ebpf.redirect_map` | Redirect is eBPF side only: passes the packet to CPU k (the same shape as DevMap.Redirect — fallback if there is no entry). |
| `bpf.CPUMap.RedirectIf` | eBPF side | `ebpf.redirect_map` | RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf). |
| `bpf.CPUMap.Remove` | user space | — | Remove is user space only: deletes CPU cpu's entry. |
| `bpf.CPUMap.Set` | user space | — | Set is user space only: sets the queue size qsize for CPU cpu's entry (nonzero — the kernel rejects 0). |

## CgroupArray

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupArray` | both | — | CgroupArray is the declaration of a BPF_MAP_TYPE_CGROUP_ARRAY (bpf-mlir's cgroup_array map): the key is a u32 in 0..MaxEntries−1, and the value is a cgroup (v2) directory (the fd from Set). |
| `bpf.CgroupArray.Clear` | user space | — | Clear is user space only: empties slot k. |
| `bpf.CgroupArray.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.CgroupArray.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u32 (a cgroup fd). |
| `bpf.CgroupArray.MaxEntries` | user space | — | MaxEntries is the maximum number of slots (a nonzero constant). |
| `bpf.CgroupArray.Set` | user space | — | Set is user space only: puts the fd of a cgroup directory in slot k (an fd from opening a cgroup v2 directory with O_RDONLY). |
| `bpf.CgroupArray.SkbUnder` | eBPF side | `ebpf.skb.under_cgroup` | SkbUnder is eBPF side only: whether the cgroup of the skb's socket is in slot k's cgroup (including its descendants) (the raw status of helper bpf_skb_under_cgroup). |
| `bpf.CgroupArray.TaskUnder` | eBPF side | `ebpf.task.under_cgroup` | TaskUnder is eBPF side only: whether the current task is in slot k's cgroup (including its descendants) (the raw status of helper bpf_current_task_under_cgroup). |

## CgroupDeviceContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupDeviceContext` | both | — | CgroupDeviceContext is the context of a cgroup_device program (struct bpf_cgroup_dev_ctx, read only). |
| `bpf.CgroupDeviceContext.AccessType` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | AccessType is eBPF side only: `(access << 16) \| type` — access is a combination of DEVCG_ACC_MKNOD 1, READ 2 and WRITE 4; type is block 1 or char 2. |
| `bpf.CgroupDeviceContext.Major` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Major is eBPF side only: the device's major number. |
| `bpf.CgroupDeviceContext.Minor` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Minor is eBPF side only: the device's minor number. |

## CgroupGetsockoptContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupGetsockoptContext` | both | — | CgroupGetsockoptContext is the context of a cgroup_sockopt program for getsockopt (struct bpf_sockopt). |
| `bpf.CgroupGetsockoptContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: the optval window [off, off+n) (the window length is the length the user passed — read and write; writes are visible to the user). |
| `bpf.CgroupGetsockoptContext.Level` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Level is eBPF side only (the same as CgroupSetsockoptContext.Level). |
| `bpf.CgroupGetsockoptContext.Optlen` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Optlen is eBPF side only: the length the handler returned (if the handler failed, the length the user passed). |
| `bpf.CgroupGetsockoptContext.Optname` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Optname is eBPF side only (the same as CgroupSetsockoptContext.Optname). |
| `bpf.CgroupGetsockoptContext.SetOptlen` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetOptlen is eBPF side only: the length returned to the user — 0 keeps the handler's result (no copy back); a negative value or one above the user's length gives EFAULT. |

## CgroupSKBEgressContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupSKBEgressContext` | both | — | CgroupSKBEgressContext is the context of a cgroup_skb egress (packets leaving the cgroup) program. |
| `bpf.CgroupSKBEgressContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only (the same as CgroupSKBIngressContext.Check). |
| `bpf.CgroupSKBEgressContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only (the same as CgroupSKBIngressContext.Len). |

## CgroupSKBIngressContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupSKBIngressContext` | both | — | CgroupSKBIngressContext is the context of a cgroup_skb ingress (packets entering the cgroup) program (struct __sk_buff). |
| `bpf.CgroupSKBIngressContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only. |
| `bpf.CgroupSKBIngressContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the packet length (__sk_buff's len — from L3). |

## CgroupSetsockoptContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupSetsockoptContext` | both | — | CgroupSetsockoptContext is the context of a cgroup_sockopt program for setsockopt (struct bpf_sockopt). |
| `bpf.CgroupSetsockoptContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: the optval window [off, off+n) (the window length is max(16, optlen) bytes — the same shape as XDPContext.Check, read and write). |
| `bpf.CgroupSetsockoptContext.Level` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Level is eBPF side only: the option level (SOL_SOCKET 1, etc.). |
| `bpf.CgroupSetsockoptContext.Optlen` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Optlen is eBPF side only: the length of the optval the user passed. |
| `bpf.CgroupSetsockoptContext.Optname` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Optname is eBPF side only: the option name (SO_PRIORITY 12, etc.). |
| `bpf.CgroupSetsockoptContext.SetOptlen` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetOptlen is eBPF side only: the length passed to the handler — −1 skips the handler (the syscall returns 0), 0 passes the user's original value, other values pass the window's value with that length. |

## CgroupSockContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupSockContext` | both | — | CgroupSockContext is the context of a cgroup_sock program (struct bpf_sock). |
| `bpf.CgroupSockContext.Family` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Family is eBPF side only: the address family (AF_INET 2, AF_INET6 10). |
| `bpf.CgroupSockContext.Protocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Protocol is eBPF side only: the protocol. |
| `bpf.CgroupSockContext.SetMark` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetMark is eBPF side only: the socket mark (SO_MARK — sock_create only). |
| `bpf.CgroupSockContext.SrcIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SrcIP4 is eBPF side only: the bound IPv4 address (network order — post_bind4 only). |
| `bpf.CgroupSockContext.SrcPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SrcPort is eBPF side only: the bound port (host order — post_bind4 / post_bind6 only). |
| `bpf.CgroupSockContext.Type` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Type is eBPF side only: the socket type (sock_create only). |

## CgroupSysctlContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgroupSysctlContext` | both | — | CgroupSysctlContext is the context of a cgroup_sysctl program (struct bpf_sysctl). |
| `bpf.CgroupSysctlContext.FilePos` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | FilePos is eBPF side only: the file position (the read or write offset). |
| `bpf.CgroupSysctlContext.SetFilePos` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetFilePos is eBPF side only: writes the file position (not measured). |
| `bpf.CgroupSysctlContext.SetNewValue` | eBPF side | `ebpf.sysctl.set_new_value` | SetNewValue is eBPF side only: replaces the written value with s (helper bpf_sysctl_set_new_value). |
| `bpf.CgroupSysctlContext.Write` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Write is eBPF side only: 1 for a write call, 0 for a read. |

## CgrpStorage

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.CgrpStorage` | both | — | CgrpStorage is the declaration of a BPF_MAP_TYPE_CGRP_STORAGE map (the owner is cgroup — since kernel 6.2). |
| `bpf.CgrpStorage.Delete` | eBPF side | `ebpf.storage.delete` | Delete is eBPF side only (the same as TaskStorage.Delete). |
| `bpf.CgrpStorage.DeleteFD` | user space | — | DeleteFD is the user-space side: deletes the value of the cgroup directory fd. |
| `bpf.CgrpStorage.Get` | eBPF side | `ebpf.storage.get`, `ebpf.ref.check` | Get is eBPF side only (the same as TaskStorage.Get — the owner is cgroup). |
| `bpf.CgrpStorage.GetFD` | user space | — | GetFD is the user-space side: the value of the cgroup directory fd. |
| `bpf.CgrpStorage.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags). |
| `bpf.CgrpStorage.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.CgrpStorage.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries). |
| `bpf.CgrpStorage.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes). |

## Config

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Config` | both | — | Config is the declaration of a **.rodata global variable** — a setting that user space sets before load (not a Go const — ifindex, thresholds, ports, etc.). |
| `bpf.Config.Get` | user space | — | Get is the user-space side: after Load the kernel's .rodata value, before Load the value Set (an error if not Set). |
| `bpf.Config.GobpfGlobal` | user space | — | GobpfGlobal is an internal API of the gobpf runtime: the section, the value type and Optional. |
| `bpf.Config.Optional` | user space | — | Optional allows a Config that is not Set (the value is 0). |
| `bpf.Config.Set` | user space | — | Set is the user-space side: decides the setting before Load (an error after Load — .rodata is frozen). |
| `bpf.Config.Value` | eBPF side | `ebpf.global.load` | Value is eBPF side only: reads the setting (bpf-mlir's ebpf.global.load — one volatile read). |

## DevMap

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.DevMap` | both | — | DevMap is the declaration of a BPF_MAP_TYPE_DEVMAP: the key is an index (u32, 0..MaxEntries-1), and the value is **the ifindex of the target interface** (u32). |
| `bpf.DevMap.Get` | user space | — | Get is user space only: the ifindex of index k (unset is an error). |
| `bpf.DevMap.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.DevMap.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key and value are u32. |
| `bpf.DevMap.MaxEntries` | user space | — | MaxEntries is the number of indexes (a nonzero constant — written in the declaration's composite literal). |
| `bpf.DevMap.Redirect` | eBPF side | `ebpf.redirect_map` | Redirect is eBPF side only: requests a redirect of the packet to the interface of index k's entry (helper bpf_redirect_map). |
| `bpf.DevMap.RedirectIf` | eBPF side | `ebpf.redirect_map` | RedirectIf is eBPF side only: if cond is true it is the same as Redirect(ctx, k, fallback); if false it returns otherwise (a constant) without requesting a redirect (bpf-mlir's `redirect_map … when %c else "<verdict>"`). |
| `bpf.DevMap.Remove` | user space | — | Remove is user space only: deletes index k's entry (later Redirects return fallback). |
| `bpf.DevMap.Set` | user space | — | Set is user space only: sets the target of index k to ifindex. |

## DevMapHash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.DevMapHash` | both | — | DevMapHash is the declaration of a BPF_MAP_TYPE_DEVMAP_HASH: the key is any u32 (a hash key, not an index), and the value is the ifindex of the target interface. |
| `bpf.DevMapHash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.DevMapHash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key and value are u32. |
| `bpf.DevMapHash.MaxEntries` | user space | — | MaxEntries is the maximum number of entries (a nonzero constant). |
| `bpf.DevMapHash.Redirect` | eBPF side | `ebpf.redirect_map` | Redirect is eBPF side only: requests a redirect of the packet to the interface at key k (the same shape as DevMap.Redirect). |
| `bpf.DevMapHash.RedirectIf` | eBPF side | `ebpf.redirect_map` | RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf). |
| `bpf.DevMapHash.Remove` | user space | — | Remove is user space only: deletes the entry at key k. |
| `bpf.DevMapHash.Set` | user space | — | Set is user space only: sets the target of key k to ifindex. |

## FexitContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.FexitContext` | both | — | FexitContext is the context of an fexit (tracing) program. |
| `bpf.FexitContext.Ret` | eBPF side | `ebpf.ctx.retval` | Ret is eBPF side only: the return value of the attached kernel function (bpf-mlir's ebpf.ctx.retval — truncates context slot nargs to R's width). |

## FlowDissectorContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.FlowDissectorContext` | both | — | FlowDissectorContext is the context of a flow_dissector program (struct __sk_buff — only the packet window and flow_keys). |
| `bpf.FlowDissectorContext.AddrProto` | eBPF side | `ebpf.flow_keys.load` | AddrProto is eBPF side only: the address ethertype (raw network order). |
| `bpf.FlowDissectorContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only). |
| `bpf.FlowDissectorContext.Dport` | eBPF side | `ebpf.flow_keys.load` | Dport is eBPF side only: the destination port (raw network order). |
| `bpf.FlowDissectorContext.Flags` | eBPF side | `ebpf.flow_keys.load` | Flags is eBPF side only: the kernel's input BPF_FLOW_DISSECTOR_F_* (PARSE_1ST_FRAG 1, STOP_AT_FLOW_LABEL 2, STOP_AT_ENCAP 4). |
| `bpf.FlowDissectorContext.FlowLabel` | eBPF side | `ebpf.flow_keys.load` | FlowLabel is eBPF side only: the IPv6 flow label (raw network order). |
| `bpf.FlowDissectorContext.IPProto` | eBPF side | `ebpf.flow_keys.load` | IPProto is eBPF side only: the transport protocol (TCP 6, UDP 17). |
| `bpf.FlowDissectorContext.IPv4Dst` | eBPF side | `ebpf.flow_keys.load` | IPv4Dst is eBPF side only: the IPv4 destination (raw network order). |
| `bpf.FlowDissectorContext.IPv4Src` | eBPF side | `ebpf.flow_keys.load` | IPv4Src is eBPF side only: the IPv4 source (raw network order). |
| `bpf.FlowDissectorContext.IsEncap` | eBPF side | `ebpf.flow_keys.load` | IsEncap is eBPF side only: 1 if it is encapsulated. |
| `bpf.FlowDissectorContext.IsFirstFrag` | eBPF side | `ebpf.flow_keys.load` | IsFirstFrag is eBPF side only: 1 if it is the first fragment. |
| `bpf.FlowDissectorContext.IsFrag` | eBPF side | `ebpf.flow_keys.load` | IsFrag is eBPF side only: 1 if it is a fragment. |
| `bpf.FlowDissectorContext.NProto` | eBPF side | `ebpf.flow_keys.load` | NProto is eBPF side only: the network ethertype (raw network order — the kernel's input). |
| `bpf.FlowDissectorContext.Nhoff` | eBPF side | `ebpf.flow_keys.load` | Nhoff is eBPF side only: the network header offset (flow_keys.nhoff). |
| `bpf.FlowDissectorContext.SetAddrProto` | eBPF side | `ebpf.flow_keys.store` | SetAddrProto is eBPF side only: writes flow_keys.addr_proto (raw network order). |
| `bpf.FlowDissectorContext.SetDport` | eBPF side | `ebpf.flow_keys.store` | SetDport is eBPF side only: writes flow_keys.dport (raw network order). |
| `bpf.FlowDissectorContext.SetFlags` | eBPF side | `ebpf.flow_keys.store` | SetFlags is eBPF side only: writes flow_keys.flags. |
| `bpf.FlowDissectorContext.SetFlowLabel` | eBPF side | `ebpf.flow_keys.store` | SetFlowLabel is eBPF side only: writes flow_keys.flow_label (raw network order). |
| `bpf.FlowDissectorContext.SetIPProto` | eBPF side | `ebpf.flow_keys.store` | SetIPProto is eBPF side only: writes flow_keys.ip_proto. |
| `bpf.FlowDissectorContext.SetIPv4Dst` | eBPF side | `ebpf.flow_keys.store` | SetIPv4Dst is eBPF side only: writes flow_keys.ipv4_dst (raw network order). |
| `bpf.FlowDissectorContext.SetIPv4Src` | eBPF side | `ebpf.flow_keys.store` | SetIPv4Src is eBPF side only: writes flow_keys.ipv4_src (raw network order). |
| `bpf.FlowDissectorContext.SetIsEncap` | eBPF side | `ebpf.flow_keys.store` | SetIsEncap is eBPF side only: writes flow_keys.is_encap. |
| `bpf.FlowDissectorContext.SetIsFirstFrag` | eBPF side | `ebpf.flow_keys.store` | SetIsFirstFrag is eBPF side only: writes flow_keys.is_first_frag. |
| `bpf.FlowDissectorContext.SetIsFrag` | eBPF side | `ebpf.flow_keys.store` | SetIsFrag is eBPF side only: writes flow_keys.is_frag. |
| `bpf.FlowDissectorContext.SetNProto` | eBPF side | `ebpf.flow_keys.store` | SetNProto is eBPF side only: writes flow_keys.n_proto (raw network order). |
| `bpf.FlowDissectorContext.SetNhoff` | eBPF side | `ebpf.flow_keys.store` | SetNhoff is eBPF side only: writes flow_keys.nhoff (the kernel clamps it afterwards). |
| `bpf.FlowDissectorContext.SetSport` | eBPF side | `ebpf.flow_keys.store` | SetSport is eBPF side only: writes flow_keys.sport (raw network order). |
| `bpf.FlowDissectorContext.SetThoff` | eBPF side | `ebpf.flow_keys.store` | SetThoff is eBPF side only: writes flow_keys.thoff (the kernel clamps it afterwards). |
| `bpf.FlowDissectorContext.Sport` | eBPF side | `ebpf.flow_keys.load` | Sport is eBPF side only: the source port (raw network order). |
| `bpf.FlowDissectorContext.Thoff` | eBPF side | `ebpf.flow_keys.load` | Thoff is eBPF side only: the transport header offset (flow_keys.thoff). |

## FsessionContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.FsessionContext` | both | — | FsessionContext is the context of an fsession (BPF_TRACE_FSESSION) program. |
| `bpf.FsessionContext.Cookie` | eBPF side | `ebpf.session.cookie.load` | Cookie reads the 8-byte value shared between entry and return (what kfunc bpf_session_cookie points to). |
| `bpf.FsessionContext.IsReturn` | eBPF side | `ebpf.session.is_return` | IsReturn reports whether the program is now running at the function's return (kfunc bpf_session_is_return). |
| `bpf.FsessionContext.SetCookie` | eBPF side | `ebpf.session.cookie.store` | SetCookie writes the 8-byte value shared between entry and return. |

## Global

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Global` | both | — | Global is the declaration of a **.bss global variable** — a counter the eBPF side counts atomically and user space reads after load (without a map). |
| `bpf.Global.Add` | eBPF side | `ebpf.global.atomic_add` | Add is eBPF side only: atomically adds d (bpf-mlir's ebpf.global.atomic_add — no result). |
| `bpf.Global.Get` | user space | — | Get is the user-space side: reads the value after load. |
| `bpf.Global.GobpfGlobal` | user space | — | GobpfGlobal is an internal API of the gobpf runtime: the section and the value type. |
| `bpf.Global.Load` | eBPF side | `ebpf.global.load` | Load is eBPF side only: reads the value (one volatile read). |

## Hash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Hash` | both | — | Hash is the declaration of a BPF_MAP_TYPE_HASH map. |
| `bpf.Hash.AddOrInit` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.atomic_add`, `ebpf.map.try_update` | AddOrInit is eBPF side only: atomically adds d to the key's value, creating the key with d if missing (V is integers only). |
| `bpf.Hash.Delete` | eBPF side | `ebpf.map.try_delete` | Delete is eBPF side only: deletes the key. |
| `bpf.Hash.Get` | user space | — | Get is user-space side only: reads the key's value (a missing key is an error wrapping ErrKeyNotExist). |
| `bpf.Hash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.Hash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes). |
| `bpf.Hash.Insert` | eBPF side | `ebpf.map.try_update` | Insert is eBPF side only: creates the key only if it is missing (BPF_NOEXIST). |
| `bpf.Hash.Iterate` | user space | — | Iterate is user-space side only: an iterator that reads every entry. |
| `bpf.Hash.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: a pointer to the key's value (nil if none). |
| `bpf.Hash.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.Hash.Put` | user space | — | Put is user-space side only: sets the key's value to v (creating it if missing). |
| `bpf.Hash.Remove` | user space | — | Remove is user-space side only: deletes the key (the name differs from the eBPF side's Delete because of status versus error — the same as Update / Put). |
| `bpf.Hash.Replace` | eBPF side | `ebpf.map.try_update` | Replace is eBPF side only: replaces only if the key exists (BPF_EXIST). |
| `bpf.Hash.Update` | eBPF side | `ebpf.map.try_update` | Update is eBPF side only: sets the key's value to v (creating it if missing — BPF_ANY). |

## HashOfMaps

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.HashOfMaps` | both | — | HashOfMaps is the declaration of a BPF_MAP_TYPE_HASH_OF_MAPS (the outer key is OK). |
| `bpf.HashOfMaps.GobpfInner` | user space | — | GobpfInner is an internal API of the gobpf runtime (the same as ArrayOfMaps.GobpfInner). |
| `bpf.HashOfMaps.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.HashOfMaps.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as ArrayOfMaps.GobpfTypes — the outer key is OK). |
| `bpf.HashOfMaps.Inner` | user space | — | Inner is the inner map's template. |
| `bpf.HashOfMaps.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.map.inner` | Lookup is eBPF side only: the inner map at outer key k (nil if none). |
| `bpf.HashOfMaps.MaxEntries` | user space | — | MaxEntries is the maximum number of outer entries (a nonzero constant). |
| `bpf.HashOfMaps.NewInner` | user space | — | NewInner is user space only (the same as ArrayOfMaps.NewInner). |
| `bpf.HashOfMaps.Remove` | user space | — | Remove is user space only (the same as ArrayOfMaps.Remove). |
| `bpf.HashOfMaps.Set` | user space | — | Set is user space only (the same as ArrayOfMaps.Set). |

## InnerMap

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.InnerMap` | both | — | InnerMap is an inner map — on the eBPF side, the handle inside the checked branch of an outer Lookup; in user space, a map created by NewInner. |
| `bpf.InnerMap.AtomicAdd` | eBPF side | `ebpf.map.atomic_add` | AtomicAdd is eBPF side only: atomically adds d to the value of the inner key (only when present — the same as Array.AtomicAdd). |
| `bpf.InnerMap.Close` | user space | — | Close is user space only: closes the user's handle (an inner map inserted into the outer map stays in the kernel while the outer map holds a reference). |
| `bpf.InnerMap.Get` | user space | — | Get is user space only: the value of the inner key. |
| `bpf.InnerMap.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: a pointer to the value of the inner key (nil if none — the same shape as Array.Lookup). |
| `bpf.InnerMap.Put` | user space | — | Put is user space only: writes a value at the inner key. |
| `bpf.InnerMap.Update` | eBPF side | `ebpf.map.update` | Update is eBPF side only: writes a value at the inner key (the same as Array.Update). |

## InnerSpec

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.InnerSpec` | both | — | InnerSpec is the declaration of the inner map's template (Kind and MaxEntries are constants). |
| `bpf.InnerSpec.Kind` | both | — | Kind is the kind of the inner map. |
| `bpf.InnerSpec.MaxEntries` | both | — | MaxEntries is the number of elements of the inner map (a nonzero constant). |

## InodeStorage

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.InodeStorage` | both | — | InodeStorage is the declaration of a BPF_MAP_TYPE_INODE_STORAGE map (the owner is inode — the kernel allows it only for lsm programs). |
| `bpf.InodeStorage.Delete` | eBPF side | `ebpf.storage.delete` | Delete is eBPF side only (the same as TaskStorage.Delete). |
| `bpf.InodeStorage.DeleteFD` | user space | — | DeleteFD is the user-space side: deletes the value of the inode of a file fd. |
| `bpf.InodeStorage.Get` | eBPF side | `ebpf.storage.get`, `ebpf.ref.check` | Get is eBPF side only (the same as TaskStorage.Get — the owner is inode). |
| `bpf.InodeStorage.GetFD` | user space | — | GetFD is the user-space side: the value of the inode of a file fd. |
| `bpf.InodeStorage.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags). |
| `bpf.InodeStorage.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.InodeStorage.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries). |
| `bpf.InodeStorage.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes). |

## IterContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.IterContext` | both | — | IterContext is the context of an iter (BPF_TRACE_ITER) program. |
| `bpf.IterContext.Seq` | eBPF side | `ebpf.ctx.arg`, `ebpf.kfield.ptr`, `ebpf.kptr.check` | Seq is the iterator output (seq of bpf_iter_meta — it can be NULL). |
| `bpf.IterContext.SeqNum` | eBPF side | `ebpf.ctx.arg`, `ebpf.kfield.load` | SeqNum is the iterator's 0-based number (seq_num of bpf_iter_meta — it advances only when there is a next element). |

## Iterator

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Iterator` | user space | — | Iterator is the user-space iterator of hash-family maps (`for it.Next() { it.Key(), it.Value() }; it.Err()`). |
| `bpf.Iterator.Err` | user space | — | Err is the iteration error (before load, after Close, or a kernel error). |
| `bpf.Iterator.Key` | user space | — | Key is the current entry's key. |
| `bpf.Iterator.Next` | user space | — | Next reads the next entry (false at the end or on an error — tell them apart with Err). |
| `bpf.Iterator.Value` | user space | — | Value is the current entry's value. |

## KprobeSessionContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.KprobeSessionContext` | both | — | KprobeSessionContext is the context of a kprobe_session (BPF_TRACE_KPROBE_SESSION) program. |
| `bpf.KprobeSessionContext.Cookie` | eBPF side | `ebpf.session.cookie.load` | Cookie is eBPF side only: the 8 bytes the entry run stored with SetCookie (ebpf.session.cookie.load). |
| `bpf.KprobeSessionContext.IsReturn` | eBPF side | `ebpf.session.is_return` | IsReturn is eBPF side only: whether the current run is at the function's return (ebpf.session.is_return). |
| `bpf.KprobeSessionContext.SetCookie` | eBPF side | `ebpf.session.cookie.store` | SetCookie is eBPF side only: stores 8 bytes to pass to the return run (ebpf.session.cookie.store). |

## KretprobeContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.KretprobeContext` | both | — | KretprobeContext is the context of a kretprobe (`//gobpf:kretprobe <kernel function>`) program. |
| `bpf.KretprobeContext.Ret` | eBPF side | `ebpf.probe.retval` | Ret is eBPF side only: the function's return value (ebpf.probe.retval). |

## LPMIterator

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LPMIterator` | user space | — | LPMIterator is the user-space iterator of LPMTrie4. |
| `bpf.LPMIterator.Err` | user space | — | Err is the iteration error (before load, after Close, or a kernel error). |
| `bpf.LPMIterator.Next` | user space | — | Next reads the next entry (false at the end or on an error — tell them apart with Err). |
| `bpf.LPMIterator.Prefix` | user space | — | Prefix is the current entry's prefix. |
| `bpf.LPMIterator.Value` | user space | — | Value is the current entry's value. |

## LPMTrie4

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LPMTrie4` | both | — | LPMTrie4 is a BPF_MAP_TYPE_LPM_TRIE table of IPv4 prefixes. |
| `bpf.LPMTrie4.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.LPMTrie4.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is LPMKey4. |
| `bpf.LPMTrie4.Iterate` | user space | — | Iterate is user space only: every prefix and value in the table (`for it.Next() { it.Prefix(), it.Value() }; it.Err()`). |
| `bpf.LPMTrie4.Lookup` | eBPF side | `ebpf.record.make`, `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: the value of the longest prefix containing addr (4 bytes in network order — the packet's byte order as is) and true, or 0 and false if none. |
| `bpf.LPMTrie4.Match` | user space | — | Match is user space only: the value of the longest prefix containing a and true, or 0 and false if none (the kernel's longest match — the same as Lookup on the eBPF side). |
| `bpf.LPMTrie4.MaxEntries` | user space | — | MaxEntries is the maximum number of prefixes (a nonzero constant — written in the declaration's composite literal). |
| `bpf.LPMTrie4.Put` | user space | — | Put is user space only: sets prefix p's value to v (replacing it if present). |
| `bpf.LPMTrie4.Remove` | user space | — | Remove is user space only: deletes prefix p (a missing prefix is a kernel ENOENT error). |

## LRUHash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LRUHash` | both | — | LRUHash is the declaration of a BPF_MAP_TYPE_LRU_HASH map. |
| `bpf.LRUHash.AddOrInit` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.atomic_add`, `ebpf.map.try_update` | AddOrInit is eBPF side only (the same as Hash.AddOrInit — when full it evicts an old entry and creates, so -E2BIG does not occur). |
| `bpf.LRUHash.Delete` | eBPF side | `ebpf.map.try_delete` | Delete is eBPF side only (the same as Hash.Delete). |
| `bpf.LRUHash.Get` | user space | — | Get is user-space side only (the same as Hash.Get). |
| `bpf.LRUHash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.LRUHash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes). |
| `bpf.LRUHash.Insert` | eBPF side | `ebpf.map.try_update` | Insert is eBPF side only (the same as Hash.Insert). |
| `bpf.LRUHash.Iterate` | user space | — | Iterate is user-space side only (the same as Hash.Iterate). |
| `bpf.LRUHash.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only (the same as Hash.Lookup). |
| `bpf.LRUHash.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.LRUHash.Put` | user space | — | Put is user-space side only (the same as Hash.Put). |
| `bpf.LRUHash.Remove` | user space | — | Remove is user-space side only (the same as Hash.Remove). |
| `bpf.LRUHash.Replace` | eBPF side | `ebpf.map.try_update` | Replace is eBPF side only (the same as Hash.Replace). |
| `bpf.LRUHash.Update` | eBPF side | `ebpf.map.try_update` | Update is eBPF side only (the same as Hash.Update — when full it evicts an old entry and creates). |

## LRUPerCPUHash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LRUPerCPUHash` | both | — | LRUPerCPUHash is the declaration of a BPF_MAP_TYPE_LRU_PERCPU_HASH map. |
| `bpf.LRUPerCPUHash.Delete` | eBPF side | `ebpf.map.try_delete` | Delete is eBPF side only (the same as PerCPUHash.Delete). |
| `bpf.LRUPerCPUHash.GetPerCPU` | user space | — | GetPerCPU is user-space side only (the same as PerCPUArray.GetPerCPU). |
| `bpf.LRUPerCPUHash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.LRUPerCPUHash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes). |
| `bpf.LRUPerCPUHash.Insert` | eBPF side | `ebpf.map.try_update` | Insert is eBPF side only (the same as PerCPUHash.Insert). |
| `bpf.LRUPerCPUHash.Iterate` | user space | — | Iterate is user-space side only (the same as PerCPUHash.Iterate). |
| `bpf.LRUPerCPUHash.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only (the same as PerCPUHash.Lookup). |
| `bpf.LRUPerCPUHash.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.LRUPerCPUHash.PutPerCPU` | user space | — | PutPerCPU is user-space side only (the same as PerCPUArray.PutPerCPU). |
| `bpf.LRUPerCPUHash.Remove` | user space | — | Remove is user-space side only (the same as Hash.Remove). |
| `bpf.LRUPerCPUHash.Replace` | eBPF side | `ebpf.map.try_update` | Replace is eBPF side only (the same as PerCPUHash.Replace). |
| `bpf.LRUPerCPUHash.Update` | eBPF side | `ebpf.map.try_update` | Update is eBPF side only (the same as PerCPUHash.Update — when full it evicts an old entry and creates). |

## LWTInContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LWTInContext` | both | — | LWTInContext is the context of an lwt_in program (struct __sk_buff). |
| `bpf.LWTInContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only, off is from the network header). |
| `bpf.LWTInContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the skb length (from the network header). |

## LWTOutContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LWTOutContext` | both | — | LWTOutContext is the context of an lwt_out program (struct __sk_buff). |
| `bpf.LWTOutContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only (the same as LWTInContext.Check). |
| `bpf.LWTOutContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only (the same as LWTInContext.Len). |

## LWTXmitContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.LWTXmitContext` | both | — | LWTXmitContext is the context of an lwt_xmit program (struct __sk_buff). |
| `bpf.LWTXmitContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only (the same as LWTInContext.Check). |
| `bpf.LWTXmitContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only (the same as LWTInContext.Len). |

## NetfilterContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.NetfilterContext` | both | — | NetfilterContext is the context of a netfilter program (struct bpf_nf_ctx — only reads through the state and skb kernel pointers). |
| `bpf.NetfilterContext.Hook` | eBPF side | `ebpf.ctx.field`, `ebpf.kfield.load` | Hook is eBPF side only: the hook number (nf_hook_state.hook — PRE_ROUTING 0, LOCAL_IN 1, FORWARD 2, LOCAL_OUT 3, POST_ROUTING 4). |
| `bpf.NetfilterContext.PF` | eBPF side | `ebpf.ctx.field`, `ebpf.kfield.load` | PF is eBPF side only: the protocol family (nf_hook_state.pf — IPv4 2, IPv6 10). |
| `bpf.NetfilterContext.SkbLen` | eBPF side | `ebpf.ctx.field`, `ebpf.kfield.load` | SkbLen is eBPF side only: the skb length (sk_buff.len — from the IP header at LOCAL_IN / LOCAL_OUT). |

## PerCPUArray

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.PerCPUArray` | both | — | PerCPUArray is the declaration of a BPF_MAP_TYPE_PERCPU_ARRAY map. |
| `bpf.PerCPUArray.AtomicAdd` | eBPF side | `ebpf.map.atomic_add` | AtomicAdd is eBPF side only: adds d to the current CPU's slot (on per-CPU maps an ordinary += is enough — no atomic is needed). |
| `bpf.PerCPUArray.GetPerCPU` | user space | — | GetPerCPU is user-space side only: the key's per-CPU values (the length is the number of possible CPUs). |
| `bpf.PerCPUArray.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.PerCPUArray.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes). |
| `bpf.PerCPUArray.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: a pointer to the current CPU's slot (nil if none). |
| `bpf.PerCPUArray.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.PerCPUArray.PutPerCPU` | user space | — | PutPerCPU is user-space side only: writes the key's per-CPU values (the length of vs is the number of possible CPUs). |
| `bpf.PerCPUArray.Update` | eBPF side | `ebpf.map.update` | Update is eBPF side only: sets the current CPU's slot to v. |

## PerCPUHash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.PerCPUHash` | both | — | PerCPUHash is the declaration of a BPF_MAP_TYPE_PERCPU_HASH map. |
| `bpf.PerCPUHash.Delete` | eBPF side | `ebpf.map.try_delete` | Delete is eBPF side only (the same as Hash.Delete — deletes the slots of every CPU). |
| `bpf.PerCPUHash.GetPerCPU` | user space | — | GetPerCPU is user-space side only (the same as PerCPUArray.GetPerCPU). |
| `bpf.PerCPUHash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.PerCPUHash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes). |
| `bpf.PerCPUHash.Insert` | eBPF side | `ebpf.map.try_update` | Insert is eBPF side only (the same as Hash.Insert). |
| `bpf.PerCPUHash.Iterate` | user space | — | Iterate is user-space side only: keys and per-CPU values (the same semantics as Hash.Iterate). |
| `bpf.PerCPUHash.Lookup` | eBPF side | `ebpf.map.lookup`, `ebpf.ref.check`, `ebpf.ref.load` | Lookup is eBPF side only: a pointer to the current CPU's slot (nil if none). |
| `bpf.PerCPUHash.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.PerCPUHash.PutPerCPU` | user space | — | PutPerCPU is user-space side only (the same as PerCPUArray.PutPerCPU). |
| `bpf.PerCPUHash.Remove` | user space | — | Remove is user-space side only (the same as Hash.Remove). |
| `bpf.PerCPUHash.Replace` | eBPF side | `ebpf.map.try_update` | Replace is eBPF side only (the same as Hash.Replace). |
| `bpf.PerCPUHash.Update` | eBPF side | `ebpf.map.try_update` | Update is eBPF side only (the same status as Hash.Update — the current CPU's slot). |

## PerfEventArray

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.PerfEventArray` | both | — | PerfEventArray is the declaration of a BPF_MAP_TYPE_PERF_EVENT_ARRAY: it outputs record V to per-CPU perf rings. |
| `bpf.PerfEventArray.GobpfEvent` | user space | — | GobpfEvent is an internal API of the gobpf runtime — the Go type of the payload record. |
| `bpf.PerfEventArray.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.PerfEventArray.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime — the declared MaxEntries (always 0 — the loader sets it to the number of possible CPUs). |
| `bpf.PerfEventArray.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key and value are u32 (CPU index → perf event fd). |
| `bpf.PerfEventArray.Output` | eBPF side | `ebpf.record.make`, `ebpf.perf.output` | Output is eBPF side only (only in fentry program bodies): outputs v to the current CPU's perf ring (helper bpf_perf_event_output, BPF_F_CURRENT_CPU), and returns **the raw status**: 0 is success, −ENOENT (−2) means the current CPU's slot has no reader, −ENOSPC (−28) is a ring overflow (counted in the reader's Lost — the count matches only after the reader drains the overflowed ring and reads the next successful output from the same CPU). |

## PerfEventContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.PerfEventContext` | both | — | PerfEventContext is the context of a perf_event program (struct bpf_perf_event_data). |
| `bpf.PerfEventContext.SamplePeriod` | eBPF side | — | SamplePeriod is eBPF side only: the period of this sample (sample_period of bpf_perf_event_data; the sample_period of the perf_event_open attr, or with freq sampling the value the kernel adjusted). |

## ProgArray

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.ProgArray` | both | — | ProgArray is the declaration of a BPF_MAP_TYPE_PROG_ARRAY map (tail calls). |
| `bpf.ProgArray.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.ProgArray.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key and value are u32. |
| `bpf.ProgArray.MaxEntries` | user space | — | MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal). |
| `bpf.ProgArray.TailCall` | eBPF side | `ebpf.tail_call` | TailCall is eBPF side only: tail calls the program in slot i (does not return on success). |
| `bpf.ProgArray.TailCallIf` | eBPF side | `ebpf.tail_call` | TailCallIf is eBPF side only: if ok is true, the same as TailCall(ctx, i) (on failure, the fallback of the following statements); **if false, it returns otherwise without a tail call or the fallback** (bpf-mlir's `ebpf.tail_call … when %c else "<verdict>"`). |

## Queue

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Queue` | both | — | Queue is the declaration of a BPF_MAP_TYPE_QUEUE (FIFO). |
| `bpf.Queue.Get` | user space | — | Get is user space only: reads the oldest element without taking it out. |
| `bpf.Queue.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.Queue.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key of a map without keys is nil. |
| `bpf.Queue.MaxEntries` | user space | — | MaxEntries is the number of elements (a nonzero constant — written in the declaration's composite literal). |
| `bpf.Queue.Peek` | eBPF side | `ebpf.map.peek` | Peek is eBPF side only: reads the oldest element without taking it out. |
| `bpf.Queue.Pop` | eBPF side | `ebpf.map.pop` | Pop is eBPF side only: takes out the oldest element. |
| `bpf.Queue.Push` | eBPF side | `ebpf.map.push` | Push is eBPF side only: inserts v (flag is a constant — PushAny / PushExist). |
| `bpf.Queue.Put` | user space | — | Put is user space only: inserts v (BPF_ANY — an error if full). |
| `bpf.Queue.Take` | user space | — | Take is user space only: takes out the oldest element (if empty, an error wrapping ebpf.ErrKeyNotExist). |

## RawTPWritableContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.RawTPWritableContext` | both | — | RawTPWritableContext is the context of a raw_tp_writable (BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE) program (bpf_raw_tracepoint_args). |
| `bpf.RawTPWritableContext.Buffer` | eBPF side | `ebpf.tp.buffer.load` | Buffer is eBPF side only: reads the i32 at offset 0 of the writable buffer (ebpf.tp.buffer.load). |
| `bpf.RawTPWritableContext.SetBuffer` | eBPF side | `ebpf.tp.buffer.store` | SetBuffer is eBPF side only: writes an i32 at offset 0 of the writable buffer (ebpf.tp.buffer.store). |

## ReuseportSockArray

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.ReuseportSockArray` | both | — | ReuseportSockArray is the declaration of a BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: the key is a u32 in 0..MaxEntries−1, and the value is a socket (the fd from Set — reads give the socket's cookie as a u64). |
| `bpf.ReuseportSockArray.Cookie` | user space | — | Cookie is user space only: the cookie of the socket at key k (an empty slot gives ErrKeyNotExist — the slot disappears when the group's socket is closed). |
| `bpf.ReuseportSockArray.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.ReuseportSockArray.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u64 (socket fd / cookie). |
| `bpf.ReuseportSockArray.MaxEntries` | user space | — | MaxEntries is the maximum number of entries (a nonzero constant). |
| `bpf.ReuseportSockArray.Remove` | user space | — | Remove is user space only: deletes the entry at key k. |
| `bpf.ReuseportSockArray.Select` | eBPF side | `ebpf.sk.select_reuseport` | Select is eBPF side only: selects the socket at key k as the group's receiver and returns the helper's raw status (0; −ENOENT for an empty slot or out of range; −EBADFD and others for a socket of another group — only in an sk_reuseport program body, outside loops). |
| `bpf.ReuseportSockArray.Set` | user space | — | Set is user space only: puts a socket fd at key k (only a bound SO_REUSEPORT UDP socket or a TCP listener — others give EINVAL / ENOTSUPP). |

## RingBuf

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.RingBuf` | both | — | RingBuf is the declaration of a BPF_MAP_TYPE_RINGBUF map. |
| `bpf.RingBuf.Discard` | eBPF side | — | Discard is eBPF side only: discards reservation e (the reader does not see it — this consumes the reservation; e cannot be used afterwards). |
| `bpf.RingBuf.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.RingBuf.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — a ring buffer has no key (nil) — the value is the event type. |
| `bpf.RingBuf.MaxEntries` | user space | — | MaxEntries is the ring buffer size (bytes — a constant power of 2, 4096 or more. |
| `bpf.RingBuf.Output` | eBPF side | `ebpf.ringbuf.reserve`, `ebpf.ringbuf.if_reserved`, `ebpf.ringbuf.store_record`, `ebpf.ringbuf.submit` | Output is eBPF side only: outputs v as a ring buffer event, and **the return value is whether the reservation succeeded and was submitted** (false means the ring buffer was full and the event was dropped). |
| `bpf.RingBuf.OutputKernelStr` | eBPF side | `ebpf.ringbuf.reserve`, `ebpf.ringbuf.if_reserved`, `ebpf.record.make`, `ebpf.ringbuf.store_record`, `ebpf.kernel.read_str`, `ebpf.ringbuf.store_field`, `ebpf.ringbuf.submit` | OutputKernelStr is eBPF side only (tracing programs — where a checked kernel pointer exists): reserves and writes event v, reads the kernel string s into the exactly one `[N]byte` (1 ≤ N ≤ 64) field of V's record with tag `gobpf:"kernelstr"` (helper probe_read_kernel_str — bpf-mlir's ebpf.kernel.read_str), writes st into the exactly one int64 field with tag `gobpf:"kernelstr_status"`, and submits. |
| `bpf.RingBuf.OutputStr` | eBPF side | `ebpf.ringbuf.reserve`, `ebpf.ringbuf.if_reserved`, `ebpf.record.make`, `ebpf.ringbuf.store_record`, `ebpf.user.read_str`, `ebpf.ringbuf.store_field`, `ebpf.ringbuf.submit` | OutputStr is eBPF side only (uprobe programs): reserves and writes event v, reads the user string s into the exactly one `[N]byte` field with tag `gobpf:"userstr"` in V's record (helper probe_read_user_str), and submits. |
| `bpf.RingBuf.OutputStrOrDiscard` | eBPF side | `ebpf.ringbuf.reserve`, `ebpf.ringbuf.if_reserved`, `ebpf.record.make`, `ebpf.ringbuf.store_record`, `ebpf.user.read_str`, `ebpf.if`, `ebpf.ringbuf.discard`, `ebpf.ringbuf.submit` | OutputStrOrDiscard is eBPF side only (uprobe programs): like OutputStr it reserves and writes event v and reads the user string s, but **an event it could not read (st < 0) is discarded without submit** (bpf-mlir's conditional discard inside present). |
| `bpf.RingBuf.Reserve` | eBPF side | — | Reserve is eBPF side only: reserves a region of V's size in the ring buffer and, if it got one, returns the reservation handle and true (otherwise nil and false). |
| `bpf.RingBuf.Submit` | eBPF side | — | Submit is eBPF side only: commits reservation e and shows it to the reader (this consumes the reservation — e cannot be used afterwards). |

## SKMsgContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SKMsgContext` | both | — | SKMsgContext is the context of an sk_msg program (struct sk_msg_md — read only). |
| `bpf.SKMsgContext.Family` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Family is eBPF side only: the socket's address family (AF_INET 2, AF_INET6 10). |
| `bpf.SKMsgContext.LocalIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalIP4 is eBPF side only: the local IPv4 address (the same byte order as RemoteIP4). |
| `bpf.SKMsgContext.LocalPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalPort is eBPF side only: the local port (host byte order). |
| `bpf.SKMsgContext.RemoteIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | RemoteIP4 is eBPF side only: the peer's IPv4 address (a u32 in network byte order as is — 127.0.0.1 reads as 0x0100007f in little endian). |
| `bpf.SKMsgContext.RemotePort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | RemotePort is eBPF side only: the peer's port — **as the kernel converts it**: the 16 bits in network byte order shifted left by 16 bits (port 8080 is htons(8080) << 16). |
| `bpf.SKMsgContext.Size` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Size is eBPF side only: the number of bytes in the message. |

## SKSKBContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SKSKBContext` | both | — | SKSKBContext is the context of an sk_skb program (struct __sk_buff — only Len and LocalPort are readable). |
| `bpf.SKSKBContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the skb length (bytes). |
| `bpf.SKSKBContext.LocalPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalPort is eBPF side only: the local port of the receiving socket (host byte order). |

## SKStorage

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SKStorage` | both | — | SKStorage is the declaration of a BPF_MAP_TYPE_SK_STORAGE map (the owner is sock). |
| `bpf.SKStorage.Delete` | eBPF side | `ebpf.storage.delete` | Delete is eBPF side only (the same as TaskStorage.Delete). |
| `bpf.SKStorage.DeleteFD` | user space | — | DeleteFD is the user-space side: deletes the value of the socket fd. |
| `bpf.SKStorage.Get` | eBPF side | `ebpf.storage.get`, `ebpf.ref.check` | Get is eBPF side only (the same as TaskStorage.Get — the owner is sock). |
| `bpf.SKStorage.GetFD` | user space | — | GetFD is the user-space side: the value of the socket fd. |
| `bpf.SKStorage.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags). |
| `bpf.SKStorage.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.SKStorage.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries). |
| `bpf.SKStorage.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes). |

## Seg6LocalContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Seg6LocalContext` | both | — | Seg6LocalContext is the context of an lwt_seg6local program (struct __sk_buff). |
| `bpf.Seg6LocalContext.Ifindex` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Ifindex is eBPF side only: the ifindex of the skb's device (the receiving device). |
| `bpf.Seg6LocalContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the skb length (from the IPv6 header). |
| `bpf.Seg6LocalContext.Mark` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Mark is eBPF side only: the skb mark. |
| `bpf.Seg6LocalContext.Priority` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Priority is eBPF side only: the skb priority. |
| `bpf.Seg6LocalContext.Protocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Protocol is eBPF side only: the skb protocol (the ethertype as a be16 — IPv6 is 0xdd86 on a little-endian host). |
| `bpf.Seg6LocalContext.SetMark` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetMark is eBPF side only: writes the skb mark (it affects the fwmark of the lookup after End.BPF). |
| `bpf.Seg6LocalContext.SetPriority` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetPriority is eBPF side only: writes the skb priority. |

## SeqFile

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SeqFile` | both | — | SeqFile is the iterator output (the kernel's struct seq_file — a local type; no field is read). |
| `bpf.SeqFile.Write` | eBPF side | `ebpf.seq.write`, `ebpf.record.make` | Write writes all bytes of the record value rec to the iterator output (helper seq_write). |

## SkLookupContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SkLookupContext` | both | — | SkLookupContext is the context of an sk_lookup program (struct bpf_sk_lookup, read only). |
| `bpf.SkLookupContext.Family` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Family is eBPF side only: the address family (AF_INET 2, AF_INET6 10). |
| `bpf.SkLookupContext.LocalIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalIP4 is eBPF side only: the destination IPv4 address (**network order** — 127.0.0.1 is 0x0100007F as a little-endian uint32). |
| `bpf.SkLookupContext.LocalPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalPort is eBPF side only: the destination port (**host order**). |
| `bpf.SkLookupContext.Protocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Protocol is eBPF side only: the IP protocol (TCP 6, UDP 17). |
| `bpf.SkLookupContext.RemotePort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | RemotePort is eBPF side only: the sender's port (**a network-order be16** — the kernel's __be16 as is, not converted on the Go side: port 7201 is 0x211C). |

## SkReuseportContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SkReuseportContext` | both | — | SkReuseportContext is the context of an sk_reuseport program (struct sk_reuseport_md — read only). |
| `bpf.SkReuseportContext.BindInany` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | BindInany is eBPF side only: 1 if the group is bound to the wildcard address (0.0.0.0 / ::). |
| `bpf.SkReuseportContext.EthProtocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | EthProtocol is eBPF side only: the skb protocol (**as a be16** — IPv4's 0x0800 is 8 as a little-endian uint32). |
| `bpf.SkReuseportContext.Hash` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Hash is eBPF side only: the 4-tuple hash (depends on the kernel's random secret). |
| `bpf.SkReuseportContext.IPProtocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | IPProtocol is eBPF side only: the protocol of the group's sockets (UDP 17, TCP 6). |
| `bpf.SkReuseportContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the skb length (for UDP, the 8-byte header + payload). |

## SockAddrContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SockAddrContext` | both | — | SockAddrContext is the context of a cgroup_sock_addr program (struct bpf_sock_addr). |
| `bpf.SockAddrContext.Family` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Family is eBPF side only: the address family. |
| `bpf.SockAddrContext.Protocol` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Protocol is eBPF side only: the protocol. |
| `bpf.SockAddrContext.SetUserIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetUserIP4 is eBPF side only: rewrites the address (network order — inet4 / udp4 hooks only). |
| `bpf.SockAddrContext.SetUserPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetUserPort is eBPF side only: rewrites the port (network order). |
| `bpf.SockAddrContext.Type` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Type is eBPF side only: the socket type (connect4 only). |
| `bpf.SockAddrContext.UserIP4` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | UserIP4 is eBPF side only: the IPv4 address the user passed (network order — inet4 / udp4 hooks only). |
| `bpf.SockAddrContext.UserPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | UserPort is eBPF side only: the port the user passed (network order — the low 16 bits). |

## SockHash

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SockHash` | both | — | SockHash is the declaration of a BPF_MAP_TYPE_SOCKHASH: the key is any K (an integer), and the value is a socket. |
| `bpf.SockHash.Assign` | eBPF side | `ebpf.sock.map_lookup`, `ebpf.sock.ref_check`, `ebpf.sk.assign`, `ebpf.sock.release` | Assign is eBPF side only: the same as SockMap.Assign (the key is K). |
| `bpf.SockHash.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.SockHash.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is K and the value is a u32 (a socket fd). |
| `bpf.SockHash.Insert` | eBPF side | `ebpf.sock.map_update` | Insert is eBPF side only (the same as SockMap.Insert — the key is K). |
| `bpf.SockHash.MaxEntries` | user space | — | MaxEntries is the maximum number of entries (a nonzero constant). |
| `bpf.SockHash.MsgRedirect` | eBPF side | `ebpf.msg.redirect` | MsgRedirect is eBPF side only (the same as SockMap.MsgRedirect — the key is K). |
| `bpf.SockHash.MsgRedirectIf` | eBPF side | `ebpf.msg.redirect` | MsgRedirectIf is eBPF side only (the same as SockMap.MsgRedirectIf — the key is K). |
| `bpf.SockHash.Redirect` | eBPF side | `ebpf.sk.redirect` | Redirect is eBPF side only (the same as SockMap.Redirect — the key is K). |
| `bpf.SockHash.RedirectIf` | eBPF side | `ebpf.sk.redirect` | RedirectIf is eBPF side only (the same as SockMap.RedirectIf — the key is K). |
| `bpf.SockHash.Remove` | user space | — | Remove is user space only: deletes the entry at key k. |
| `bpf.SockHash.Set` | user space | — | Set is user space only: puts a socket fd at key k. |

## SockMap

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SockMap` | both | — | SockMap is the declaration of a BPF_MAP_TYPE_SOCKMAP: the key is a u32 in 0..MaxEntries−1, and the value is a socket (the fd from Set — the kernel holds a reference to the socket). |
| `bpf.SockMap.Assign` | eBPF side | `ebpf.sock.map_lookup`, `ebpf.sock.ref_check`, `ebpf.sk.assign`, `ebpf.sock.release` | Assign is eBPF side only (an sk_lookup program body — bpf-mlir's ebpf.sk.assign): looks up the socket in slot k, and if present (found = true) selects it as the result of this lookup and releases the reference (the frontend assembles lookup, check, select and release — the reference never reaches Go). |
| `bpf.SockMap.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.SockMap.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u32 (a socket fd). |
| `bpf.SockMap.Insert` | eBPF side | `ebpf.sock.map_update` | Insert is eBPF side only: puts the sock_ops callback's socket at key k and returns the helper's raw status (0 or a negative errno) (sock_ops programs only — outside loop bodies, flags is a constant). |
| `bpf.SockMap.MaxEntries` | user space | — | MaxEntries is the maximum number of entries (a nonzero constant). |
| `bpf.SockMap.MsgRedirect` | eBPF side | `ebpf.msg.redirect` | MsgRedirect is eBPF side only: moves the message to the socket at key k (the direction is a constant — only as a top-level return of the body). |
| `bpf.SockMap.MsgRedirectIf` | eBPF side | `ebpf.msg.redirect` | MsgRedirectIf is eBPF side only: MsgRedirect if cond, otherwise otherwise (a constant verdict). |
| `bpf.SockMap.Redirect` | eBPF side | `ebpf.sk.redirect` | Redirect is eBPF side only: moves the skb to the socket at key k (the direction is a constant — only as a top-level return of the body). |
| `bpf.SockMap.RedirectIf` | eBPF side | `ebpf.sk.redirect` | RedirectIf is eBPF side only: Redirect if cond, otherwise otherwise (a constant verdict). |
| `bpf.SockMap.Remove` | user space | — | Remove is user space only: deletes the entry at key k. |
| `bpf.SockMap.Set` | user space | — | Set is user space only: puts a socket fd at key k (kernel errnos — EOPNOTSUPP for an unconnected TCP socket, ENOTSOCK for an fd that is not a socket). |

## SockOpsContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SockOpsContext` | both | — | SockOpsContext is the context of a sock_ops (callbacks for TCP socket operations — attached to a cgroup) program (struct bpf_sock_ops). |
| `bpf.SockOpsContext.Family` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Family is eBPF side only: the address family. |
| `bpf.SockOpsContext.LocalPort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | LocalPort is eBPF side only: the local port (host order). |
| `bpf.SockOpsContext.Op` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Op is eBPF side only: the callback kind (BPF_SOCK_OPS_TCP_CONNECT_CB 3, ACTIVE_ESTABLISHED_CB 4, PASSIVE_ESTABLISHED_CB 5, etc.). |
| `bpf.SockOpsContext.RemotePort` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | RemotePort is eBPF side only: the peer's port (network order in the upper 16 bits — as in the kernel's table). |
| `bpf.SockOpsContext.SetReply` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetReply is eBPF side only: the callback's reply (its meaning depends on op — for example the RTO for TIMEOUT_INIT). |

## SocketFilterContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.SocketFilterContext` | both | — | SocketFilterContext is the context of a socket_filter (SO_ATTACH_BPF — attached to a socket) program (struct __sk_buff). |
| `bpf.SocketFilterContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the packet length (__sk_buff's len). |

## Stack

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Stack` | both | — | Stack is the declaration of a BPF_MAP_TYPE_STACK (LIFO). |
| `bpf.Stack.Get` | user space | — | Get is user space only: reads the newest element without taking it out. |
| `bpf.Stack.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.Stack.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Queue.GobpfTypes). |
| `bpf.Stack.MaxEntries` | user space | — | MaxEntries is the number of elements (a nonzero constant). |
| `bpf.Stack.Peek` | eBPF side | `ebpf.map.peek` | Peek is eBPF side only: reads the newest element without taking it out. |
| `bpf.Stack.Pop` | eBPF side | `ebpf.map.pop` | Pop is eBPF side only: takes out the newest element. |
| `bpf.Stack.Push` | eBPF side | `ebpf.map.push` | Push is eBPF side only (the same as Queue.Push). |
| `bpf.Stack.Put` | user space | — | Put is user space only (the same as Queue.Put). |
| `bpf.Stack.Take` | user space | — | Take is user space only: takes out the newest element. |

## StackBuildID

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.StackBuildID` | both | — | StackBuildID is the declaration of a build id stack map (BPF_MAP_TYPE_STACK_TRACE + BPF_F_STACK_BUILD_ID): the key is an id (u32), and the value is Depth 32-byte elements `struct bpf_stack_build_id { s32 status; u8 build_id[20]; union { u64 offset; u64 ip; } }`. |
| `bpf.StackBuildID.Delete` | user space | — | Delete is user space only: deletes stack id (frees the bucket). |
| `bpf.StackBuildID.Depth` | user space | — | Depth is the maximum number of elements in one stack (a nonzero constant — each element is 32 bytes). |
| `bpf.StackBuildID.Get` | user space | — | Get is user space only: the elements of stack id (bindrt.DecodeStackBuildID — stops at the first empty element, per-element status as is). |
| `bpf.StackBuildID.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime: BPF_F_STACK_BUILD_ID (32 — the flags of a build id stack map). |
| `bpf.StackBuildID.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.StackBuildID.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is [Depth]StackBuildIDEntry. |
| `bpf.StackBuildID.MaxEntries` | user space | — | MaxEntries is the number of stack buckets (a positive constant). |
| `bpf.StackBuildID.UserID` | eBPF side | `ebpf.stack.user_id` | UserID is the same as StackTrace.UserID (build id stack). |
| `bpf.StackBuildID.UserIDReuse` | eBPF side | `ebpf.stack.user_id` | UserIDReuse is the same as StackTrace.UserIDReuse (build id stack). |

## StackTrace

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.StackTrace` | both | — | StackTrace is the declaration of a BPF_MAP_TYPE_STACK_TRACE: the key is a stack id (u32), and the value is the kernel stack's IPs (u64 × Depth). |
| `bpf.StackTrace.Delete` | user space | — | Delete is user space only: deletes stack id (frees the bucket). |
| `bpf.StackTrace.Depth` | user space | — | Depth is the maximum number of IPs in one stack (a nonzero constant). |
| `bpf.StackTrace.Get` | user space | — | Get is user space only: the IPs of stack id (trailing zeros removed — the first is the innermost frame). |
| `bpf.StackTrace.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.StackTrace.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is a u32 and the value is [Depth]uint64. |
| `bpf.StackTrace.KernelID` | eBPF side | `ebpf.stack.kernel_id` | KernelID is eBPF side only (only in fentry program bodies): records the current kernel stack, excluding the first skip frames, and returns **the raw status** (helper bpf_get_stackid). |
| `bpf.StackTrace.KernelIDReuse` | eBPF side | `ebpf.stack.kernel_id` | KernelIDReuse is the same as KernelID, but overwrites the previous stack on a bucket collision (BPF_F_REUSE_STACKID — never −EEXIST, but −ENOMEM (−12) if there is no free element). |
| `bpf.StackTrace.MaxEntries` | user space | — | MaxEntries is the number of stacks it can hold (elements — a nonzero constant. |
| `bpf.StackTrace.UserID` | eBPF side | `ebpf.stack.user_id` | UserID is eBPF side only (only in uprobe, kprobe and fentry program bodies): records the current task's user-space stack, excluding the first skip frames, and returns **the raw status** (an id ≥ 0 or a negative errno — a bucket collision gives −EEXIST). |
| `bpf.StackTrace.UserIDReuse` | eBPF side | `ebpf.stack.user_id` | UserIDReuse is the same as UserID, but overwrites the previous stack on a bucket collision (BPF_F_REUSE_STACKID — −ENOMEM if there is no free element). |

## TCActContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TCActContext` | both | — | TCActContext is the context of a sched_act program (struct __sk_buff). |
| `bpf.TCActContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: if the packet window [off, off+n) exists, returns a Window and true (the same shape as XDPContext.Check — read only). |
| `bpf.TCActContext.Len` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | Len is eBPF side only: the skb length (bytes). |
| `bpf.TCActContext.SetMark` | eBPF side | `ebpf.ctx.field`, `ebpf.ctx.field.store` | SetMark is eBPF side only: writes the skb mark (in a test run it appears as the mark of the ctx_out __sk_buff). |

## TCEgressContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TCEgressContext` | both | — | TCEgressContext is the context of a tcx egress sched_cls program. |
| `bpf.TCEgressContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only (the same as TCIngressContext.Check). |
| `bpf.TCEgressContext.Redirect` | eBPF side | `ebpf.redirect` | Redirect is eBPF side only (the same as TCIngressContext.Redirect — the return value is the requested action, not whether delivery succeeded). |
| `bpf.TCEgressContext.RedirectIf` | eBPF side | `ebpf.redirect` | RedirectIf is eBPF side only (the same as TCIngressContext.RedirectIf — the return value is the requested action, not whether delivery succeeded). |

## TCIngressContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TCIngressContext` | both | — | TCIngressContext is the context of a tcx ingress sched_cls program (struct __sk_buff). |
| `bpf.TCIngressContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: (window, true) if the packet's [off, off+n) is in range. |
| `bpf.TCIngressContext.Redirect` | eBPF side | `ebpf.redirect` | Redirect is eBPF side only: **the return value is the requested action (TC_ACT_REDIRECT), not whether delivery succeeded** — even for an ifindex that does not exist it returns REDIRECT and the packet does not arrive. |
| `bpf.TCIngressContext.RedirectIf` | eBPF side | `ebpf.redirect` | RedirectIf is eBPF side only: **the return value is the requested action, not whether delivery succeeded** (the same as Redirect). |

## TCPCongestionOps

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TCPCongestionOps` | both | — | TCPCongestionOps is the declaration of a tcp_congestion_ops struct_ops map. |
| `bpf.TCPCongestionOps.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.TCPCongestionOps.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime — a struct_ops map has no MaxEntries field and is 1 (one value at key 0). |
| `bpf.TCPCongestionOps.GobpfStructOps` | user space | — | GobpfStructOps is an internal API of the gobpf runtime — the struct_ops type and the registered name. |
| `bpf.TCPCongestionOps.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and there is no value (the kernel's bpf_struct_ops_<type> — the loader writes it). |
| `bpf.TCPCongestionOps.Name` | user space | — | Name is the registered name (the name shown in tcp_available_congestion_control — selected with setsockopt TCP_CONGESTION). |

## TaskStorage

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TaskStorage` | both | — | TaskStorage is the declaration of a BPF_MAP_TYPE_TASK_STORAGE map (the owner is task_struct — since kernel 5.11). |
| `bpf.TaskStorage.Delete` | eBPF side | `ebpf.storage.delete` | Delete is eBPF side only: deletes the owner's value (raw status — the frontend stops a statement that discards it). |
| `bpf.TaskStorage.DeleteFD` | user space | — | DeleteFD is the user-space side: deletes the value of the pidfd's task. |
| `bpf.TaskStorage.Get` | eBPF side | `ebpf.storage.get`, `ebpf.ref.check` | Get is eBPF side only: a pointer to the owner's value (if missing and create is Create, it is created as 0; nil if it cannot be created). |
| `bpf.TaskStorage.GetFD` | user space | — | GetFD is the user-space side: the value of the pidfd's task. |
| `bpf.TaskStorage.GobpfMapFlags` | user space | — | GobpfMapFlags is an internal API of the gobpf runtime: the flags of a local storage map are BPF_F_NO_PREALLOC (1 — the kernel requires it). |
| `bpf.TaskStorage.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.TaskStorage.GobpfMaxEntries` | user space | — | GobpfMaxEntries is an internal API of the gobpf runtime: max_entries of a local storage map is 0 (it has no MaxEntries field). |
| `bpf.TaskStorage.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is int32 (the owner's fd). |

## Timer

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Timer` | both | — | Timer is a record field type (struct bpf_timer — 16 bytes). |
| `bpf.Timer.Init` | eBPF side | `ebpf.timer.init` | Init is eBPF side only: initializes the timer with the monotonic clock (helper bpf_timer_init — the map is the map of the Lookup that returned t) and returns **the raw status**: 0 is success; the second and later calls give −EBUSY (−16) and the timer stays initialized. |
| `bpf.Timer.SetCallback` | eBPF side | `ebpf.timer.set_callback`, `ebpf.timer.callback`, `ebpf.timer.done` | SetCallback is eBPF side only: sets the timer's callback to cb (helper bpf_timer_set_callback). |
| `bpf.Timer.Start` | eBPF side | `ebpf.timer.start` | Start is eBPF side only: starts the timer to fire after ns (relative nanoseconds) (helper bpf_timer_start, flags 0 — inside the then where the program's Init status is 0, or a restart of its own timer inside the timer's callback (a periodic timer)). |

## TracepointContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.TracepointContext` | both | — | TracepointContext is the context of a tracepoint (a tracefs event — `<category>/<event>`) program. |
| `bpf.TracepointContext.Event` | eBPF side | `ebpf.tp.field` | Event is eBPF side only: the event record. |

## UretprobeContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.UretprobeContext` | both | — | UretprobeContext is the context of a uretprobe (`//gobpf:uretprobe <binary path> <symbol>` — the path rules are the same as uprobe) program. |
| `bpf.UretprobeContext.Ret` | eBPF side | `ebpf.probe.retval` | Ret is eBPF side only: the function's return value (ebpf.probe.retval). |

## UserRingBuf

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.UserRingBuf` | both | — | UserRingBuf is a ring buffer from user space to the kernel (BPF_MAP_TYPE_USER_RINGBUF): |
| `bpf.UserRingBuf.Drain` | eBPF side | `ebpf.user_ringbuf.drain`, `ebpf.user_ringbuf.callback`, `ebpf.user_ringbuf.done`, `ebpf.dynptr.read` | Drain is eBPF side only: passes the written samples, oldest first, one at a time to callback cb (helper bpf_user_ringbuf_drain, flags 0). |

## Window

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.Window` | both | — | Window is a checked range of the packet (valid only inside ctx.Check's in_range). |
| `bpf.Window.BE16` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | BE16 is the big-endian 16 bits starting at byte i of the window (network order). |
| `bpf.Window.BE32` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | BE32 is big-endian 32 bits. |
| `bpf.Window.BE64` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | BE64 is big-endian 64 bits. |
| `bpf.Window.LE16` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | LE16 is little-endian 16 bits. |
| `bpf.Window.LE32` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | LE32 is little-endian 32 bits. |
| `bpf.Window.LE64` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | LE64 is little-endian 64 bits. |
| `bpf.Window.SetBE16` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetBE16 is eBPF side only: writes v in big endian (network order) (the same rules as SetU8). |
| `bpf.Window.SetBE32` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetBE32 is eBPF side only: writes v in big endian. |
| `bpf.Window.SetBE64` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetBE64 is eBPF side only: writes v in big endian. |
| `bpf.Window.SetLE16` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetLE16 is eBPF side only: writes v in little endian. |
| `bpf.Window.SetLE32` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetLE32 is eBPF side only: writes v in little endian. |
| `bpf.Window.SetLE64` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetLE64 is eBPF side only: writes v in little endian. |
| `bpf.Window.SetU8` | eBPF side | `ebpf.packet.store`, `ebpf.byteorder.to_be` | SetU8 is eBPF side only: writes 1 byte at constant index i of the window (**xdp only** — writes to a sched_cls window are stopped by the frontend, GB025). |
| `bpf.Window.U8` | eBPF side | `ebpf.packet.window_load`, `ebpf.byteorder.from_be` | U8 is byte i of the window. |

## XDPContext

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.XDPContext` | both | — | XDPContext is the context of an xdp program (struct xdp_md). |
| `bpf.XDPContext.AdjustHead` | eBPF side | `ebpf.xdp.adjust_head` | AdjustHead is eBPF side only: moves the start of the packet by delta bytes (positive trims, negative grows — the kernel checks the headroom) and returns the helper's **raw status** (0 or a negative errno — on failure −22 and the packet is unchanged). |
| `bpf.XDPContext.AdjustTail` | eBPF side | `ebpf.xdp.adjust_tail` | AdjustTail is eBPF side only: moves the end of the packet by delta bytes — **shrinking only**: delta is a constant ≤ 0 (in bpf-mlir, growing depends on the driver's tailroom, which is not measured). |
| `bpf.XDPContext.Check` | eBPF side | `ebpf.packet.check` | Check is eBPF side only: (window, true) if the packet's [off, off+n) is in range. |

## XSKMap

| Identifier | Side | Lowering | Description |
|---|---|---|---|
| `bpf.XSKMap` | both | — | XSKMap is the declaration of a BPF_MAP_TYPE_XSKMAP: the key is an rx queue number, and the value is an AF_XDP socket fd (at Set — the kernel holds a reference to the socket). |
| `bpf.XSKMap.GobpfMapKind` | user space | — | GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind). |
| `bpf.XSKMap.GobpfTypes` | user space | — | GobpfTypes is an internal API of the gobpf runtime — the key and value are u32. |
| `bpf.XSKMap.MaxEntries` | user space | — | MaxEntries is the maximum number of queues (a nonzero constant). |
| `bpf.XSKMap.Redirect` | eBPF side | `ebpf.redirect_map` | Redirect is eBPF side only: passes the packet to the AF_XDP socket of queue k (the same shape as DevMap.Redirect). |
| `bpf.XSKMap.RedirectIf` | eBPF side | `ebpf.redirect_map` | RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf). |
| `bpf.XSKMap.Remove` | user space | — | Remove is user space only: deletes queue's entry. |
| `bpf.XSKMap.Set` | user space | — | Set is user space only: puts an AF_XDP socket fd in queue's entry. |

## gobpf (the user-space runtime)

Every identifier of the gobpf package is user space only (using one on the eBPF side is GB003). Only attach and `Objects.Program` may take a program function value (programValueTakers — anything else is GB004).

| Identifier | Description |
|---|---|
| `gobpf.AttachCgroup` | AttachCgroup attaches a cgroup-family program (cgroup_skb, cgroup_sock, cgroup_sock_addr, sock_ops — a function value) to the cgroup v2 directory cgroupDir (cilium's link.AttachCgroup; the attach type follows from the program's kind and hook — the context type and the directive). |
| `gobpf.AttachExt` | AttachExt attaches an ext program (a function value) with a link to its load-time target (a function of a program of the same Load — directive `//gobpf:ext <program> <function>`) (cilium's link.AttachFreplace(nil, "", prog)). |
| `gobpf.AttachFentry` | AttachFentry attaches a fentry program (a function value) to the kernel function in its directive `//gobpf:fentry <fn>` (cilium's link.AttachTracing; cilium resolves the attach target from the ELF section `fentry/<fn>` with the kernel's BTF). |
| `gobpf.AttachFexit` | AttachFexit attaches a fexit program (a function value) to the kernel function in its directive `//gobpf:fexit <fn> nargs=<N>` (cilium's link.AttachTracing). |
| `gobpf.AttachFmodRet` | AttachFmodRet attaches an fmod_ret program (a function value) to the entry trampoline of the kernel function in its directive `//gobpf:fmod_ret <fn> nargs=<N>` (cilium's link.AttachTracing with AttachModifyReturn). |
| `gobpf.AttachFsession` | AttachFsession attaches an fsession program (a function value) to the entry and return of the kernel function in its directive (link.AttachTracing with AttachTraceFSession, which needs cilium/ebpf fsession support — upstream PR #2108). |
| `gobpf.AttachIter` | AttachIter makes an iterator link of an iter program (a function value) over the map named by its directive (cilium's link.AttachIter). |
| `gobpf.AttachKprobe` | AttachKprobe attaches a kprobe program (a function value) to the entry of the kernel function in its directive `//gobpf:kprobe <fn>` (cilium's link.Kprobe). |
| `gobpf.AttachKprobeMulti` | AttachKprobeMulti attaches a kprobe_multi / kretprobe_multi program (a function value) to the list of kernel functions in its directive with one link (cilium's link.KprobeMulti / KretprobeMulti). |
| `gobpf.AttachKprobeSession` | AttachKprobeSession attaches a kprobe_session program (a function value) to the entry and return of the kernel function in its directive `//gobpf:kprobe_session <fn>` (cilium's link.KprobeMulti with Session: true — a kprobe.multi link). |
| `gobpf.AttachKretprobe` | AttachKretprobe attaches a kretprobe program (a function value) to the return of the kernel function in its directive `//gobpf:kretprobe <fn>` (cilium's link.Kretprobe). |
| `gobpf.AttachKsyscall` | AttachKsyscall attaches a ksyscall program (a function value) to the entry of the syscall wrapper `__x64_sys_<syscall>` for the syscall in its directive `//gobpf:ksyscall <syscall>`. |
| `gobpf.AttachLSM` | AttachLSM attaches an lsm / lsm.s program (a function value) to the LSM hook in its directive `//gobpf:lsm <hook>` / `//gobpf:lsm_s <hook>` (cilium's link.AttachLSM, BPF_LSM_MAC). |
| `gobpf.AttachLWTRoute` | AttachLWTRoute adds the route `<dst> dev <oif> encap bpf [in <in>] [out <out>] [xmit <xmit>]` in the netns at netnsPath (RTM_NEWROUTE with CREATE\|EXCL — fnIn / fnOut / fnXmit are function values, nil for unused stages). |
| `gobpf.AttachNetNs` | AttachNetNs attaches an sk_lookup program (a function value) to the netns at a netns path (such as /run/netns/<name> or /proc/<pid>/ns/net) (cilium's link.AttachNetNs, BPF_LINK_CREATE). |
| `gobpf.AttachNetfilter` | AttachNetfilter attaches a netfilter program (a function value) to the pf / hook of the netns at a netns path (such as /var/run/netns/<name>) with a priority (cilium's link.AttachNetfilter). |
| `gobpf.AttachPerfEvent` | AttachPerfEvent attaches a perf_event program (a function value) to the fd of an event the user opened with perf_event_open (BPF_LINK_CREATE, cilium's link.AttachRawLink with ebpf.AttachPerfEvent). |
| `gobpf.AttachRawTP` | AttachRawTP attaches a raw_tp program (a function value) to the raw tracepoint in its directive `//gobpf:raw_tp <tracepoint>` (cilium's link.AttachRawTracepoint). |
| `gobpf.AttachRawTPWritable` | AttachRawTPWritable attaches a raw_tp_writable program (a function value) to the writable raw tracepoint in its directive `//gobpf:raw_tp_writable <tracepoint>` (cilium's link.AttachRawTracepoint accepts RawTracepointWritable). |
| `gobpf.AttachReuseport` | AttachReuseport attaches an sk_reuseport program (a function value) to the group of a bound SO_REUSEPORT socket fd with SO_ATTACH_REUSEPORT_EBPF (cilium has no entry for it, so gobpf calls setsockopt). |
| `gobpf.AttachSeg6Local` | AttachSeg6Local attaches an lwt_seg6local program (a function value) to the route `<sid>/128 dev <oif> encap seg6local action End.BPF` in the netns at netnsPath (the main table — RTM_NEWROUTE with CREATE\|EXCL). |
| `gobpf.AttachSocketFilter` | AttachSocketFilter attaches a socket_filter program (a function value) to a socket fd with SO_ATTACH_BPF. |
| `gobpf.AttachSockmap` | AttachSockmap attaches an sk_skb or sk_msg program (a function value) to the sockmap / sockhash in its directive `//gobpf:sk_skb <map>` with **BPF_PROG_ATTACH** (bpf-mlir's livecaps.AttachSockmapProgAttach. |
| `gobpf.AttachStructOps` | AttachStructOps registers a struct_ops map (a pointer to the Go variable, such as &CC) with a link (cilium's link.AttachStructOps). |
| `gobpf.AttachTCX` | AttachTCX attaches a sched_cls program (a function value) to the tcx of the interface ifindex. |
| `gobpf.AttachTPBTF` | AttachTPBTF attaches a tp_btf program (a function value) to the tracepoint in its directive `//gobpf:tp_btf <tracepoint>` (cilium's link.AttachTracing). |
| `gobpf.AttachTracepoint` | AttachTracepoint attaches a tracepoint program (a function value) to the tracefs event in its directive `//gobpf:tracepoint <category>/<event>` (bpf-mlir's livecaps.AttachTracepointAllCPUs: it opens a perf event on every online CPU and attaches the program to the first event. |
| `gobpf.AttachUSDT` | AttachUSDT attaches a usdt program (a function value) to every USDT point `<provider>:<name>` (its directive) in the binary given to Load's WithUprobeTarget (bpf-mlir's glue livecaps.AttachUSDT: it reads the notes, writes the spec of point i (note order) at key i of the compiler's spec map `__ebpf_usdt_spec_<program>`, and attaches with cilium's Executable.Uprobe using Address (the point's file offset), Cookie i and RefCtrOffset (for points with a semaphore — the kernel raises the semaphore only while attached)). |
| `gobpf.AttachUprobe` | AttachUprobe attaches a uprobe program (a function value) to the entry of the symbol in the binary given to Load's WithUprobeTarget. |
| `gobpf.AttachUprobeMulti` | AttachUprobeMulti attaches a uprobe_multi / uretprobe_multi program (a function value) to the list of symbols in the binary given to Load's WithUprobeTarget with one link (cilium's Executable.UprobeMulti / UretprobeMulti). |
| `gobpf.AttachUretprobe` | AttachUretprobe attaches a uretprobe program (a function value) to the return of the symbol in the binary given to Load's WithUprobeTarget (the same fd and file offset check and link info confirmation as AttachUprobe). |
| `gobpf.AttachXDP` | AttachXDP attaches an xdp program (a function value) to the interface ifindex. |
| `gobpf.CheckLayoutOf` | CheckLayoutOf checks o's record layouts and map declarations against o's ELF (the same as CheckLayout in bpf-mlir's bindgen): |
| `gobpf.CheckSchemaOf` | CheckSchemaOf confirms that the schema SHA-256 in the ELF's .ebpf_requirements equals the value at generation (bindrt.CheckSchema — the fix hint is gobpf's procedure). |
| `gobpf.CheckTarget` | CheckTarget checks the embedded ELF's requirements against caps and returns every Unmet. |
| `gobpf.CiliumFork` | CiliumFork is the version of the local cilium/ebpf fork used for the build (go-bpf-mlir's third_party/cilium-ebpf). |
| `gobpf.CiliumForkPatches` | CiliumForkPatches is the fork's base and the applied upstream changes (an open PR as its number and head hash, a merged one as its main hash). |
| `gobpf.ConfigNotSetError` | ConfigNotSetError lists the (non-Optional) Configs that were not Set before Load. |
| `gobpf.ConfigNotSetError.Configs` |  |
| `gobpf.ConfigNotSetError.Error` |  |
| `gobpf.DecodeLE` | DecodeLE reads the little-endian integer at the start of b into *dst (the width is *dst's type — used by the generated Decode; the user does not call it). |
| `gobpf.Decoder` | Decoder is the generated gobpf_T's Decode (reads by offset — the same shape as bpf-mlir's bindgen). |
| `gobpf.ErrAlreadyLoaded` | ErrAlreadyLoaded means Load was called twice (before Close). |
| `gobpf.ErrNoObject` | ErrNoObject means there is no embedded object (go generate was not run, or a build for an unsupported GOOS / GOARCH). |
| `gobpf.ErrReaderClosed` | ErrReaderClosed is returned by a Read after Close (the Reader or the Objects was closed). |
| `gobpf.ErrUserRingFull` | ErrUserRingFull means the ring has no space at Write (nothing can be written until the eBPF side's Drain advances the consumer). |
| `gobpf.Global` | Global is a global variable the generated file registers (Var is a pointer to a bpf.Config / bpf.Global variable). |
| `gobpf.Global.Pos` | position of the Go declaration (for error messages) |
| `gobpf.Global.Symbol` |  |
| `gobpf.Global.Var` |  |
| `gobpf.HintError` | HintError is a load error with a likely cause (Hint) added. |
| `gobpf.HintError.Err` |  |
| `gobpf.HintError.Error` |  |
| `gobpf.HintError.Format` | Format passes `%+v` and `%-Nv` to the original error: cilium's *ebpf.VerifierError prints only the last log line with `%v`, the whole log with `%+v` (bpf-mlir v0.6.0's line_info — including the Go line before each instruction), and the last N lines with `%-Nv`. |
| `gobpf.HintError.Hint` |  |
| `gobpf.HintError.Unwrap` |  |
| `gobpf.LWTRoute` | LWTRoute is an lwt route in a test netns. |
| `gobpf.LWTRoute.Close` | Close deletes the route (RTM_DELROUTE in the same netns — with the guard). |
| `gobpf.Load` | Load is the default load entry: it checks the requirements against caps (precheck), and on a mismatch that stops the load returns *TargetError without creating any kernel object. |
| `gobpf.LoadCollectionSpec` | LoadCollectionSpec parses the embedded ELF (without touching the kernel). |
| `gobpf.LoadOption` | LoadOption is an extra input to Load. |
| `gobpf.LoadUnchecked` | LoadUnchecked loads the embedded ELF **without checking the requirements**. |
| `gobpf.LoaderDecl` | LoaderDecl is gobpf's loader declaration (bpf-mlir's requirements_format.md): cilium v0.22 (requirements.Cilium022) with **ksyscall_attach changed to prefix, usdt_attach to ref_ctr, sockmap_attach to prog_attach, lsm_cgroup_load to btf_id (the local cilium fork looks up the BTF id through upstream PR #2115), and fsession_load to btf_id (PR #2108)**. |
| `gobpf.Map` | Map is the user's map variable (Var is a pointer to the variable) and the ELF's map symbol. |
| `gobpf.Map.Pos` | position of the Go declaration (package-relative file:line:col — written by the generated file; check errors point to it) |
| `gobpf.Map.Symbol` |  |
| `gobpf.Map.Var` |  |
| `gobpf.MapDeclError` | MapDeclError is a mismatch between the Go map declarations and the ELF requirements' map rows (bindrt.CheckMapDecls — both directions; an alias of the bindrt type). |
| `gobpf.MapDeclProblem` | MapDeclProblem is one mismatch in a MapDeclError (an alias of the bindrt type). |
| `gobpf.MapValue` | MapValue is a map whose value is a record, and that record (layout.CheckMapValues checks it against the ELF's BTF .maps). |
| `gobpf.NewPerfReader` | NewPerfReader creates a reader for a loaded perf event map. |
| `gobpf.NewReader` | NewReader creates a reader for a loaded ring buffer. |
| `gobpf.NewUserRingWriter` | NewUserRingWriter creates a writer for a loaded user ring buffer (mmap). |
| `gobpf.Object` | Object is the embedded object the generated file registers. |
| `gobpf.Object.ELF` |  |
| `gobpf.Object.Globals` | global variables (bpf.Config in .rodata, bpf.Global in .bss; Load runs CheckGlobals and sets .rodata) |
| `gobpf.Object.MapValues` | maps whose value is a record, and that record |
| `gobpf.Object.Maps` |  |
| `gobpf.Object.PerfRecords` | perf_event_arrays and their payload records (the ELF map value is u32, so only V is checked) |
| `gobpf.Object.Programs` |  |
| `gobpf.Object.Records` | the record layout table (checked against the ELF's BTF before load) |
| `gobpf.Object.RingBufRecords` | ring buffers and their event records (the BTF map definition has no value, so outside CheckMapValues; only V is checked) |
| `gobpf.Object.SchemaSHA256` | SHA-256 of the schema file at generation (checked against the ELF's .ebpf_requirements) |
| `gobpf.Object.TailSlots` | prog_array slot declarations (bpf.TailSlot; Load checks them against the ELF's tailslot rows and sets them after load) |
| `gobpf.Objects` | Objects are the loaded programs and maps. |
| `gobpf.Objects.Close` | Close closes the loaded programs and maps and puts the map variables in the after-Close state. |
| `gobpf.Objects.Program` | Program returns the loaded program for a program function value (such as CountPackets). |
| `gobpf.PerfReader` | PerfReader is the user-space reader of a perf event map (bpf.PerfEventArray[V]): it creates a perf ring for every possible CPU and registers them in the map (it wraps cilium's perf.Reader). |
| `gobpf.PerfReader.Close` | Close closes the reader (a second call does nothing). |
| `gobpf.PerfReader.Lost` | Lost is the sum of the overflow notices read so far. |
| `gobpf.PerfReader.Read` | Read waits for and reads the next result (os.ErrDeadlineExceeded at the SetDeadline deadline). |
| `gobpf.PerfReader.SetDeadline` | SetDeadline sets the deadline for Read (the zero value means no deadline). |
| `gobpf.PerfRecord` | PerfRecord is one result of PerfReader.Read. |
| `gobpf.PerfRecord.CPU` |  |
| `gobpf.PerfRecord.Lost` |  |
| `gobpf.PerfRecord.Value` |  |
| `gobpf.PrecheckError` | PrecheckError is a failure of the default load entry's target check itself (a caps probe error, unreadable requirements, nil caps and so on). |
| `gobpf.Program` | Program is the user's program function and the ELF's program symbol. |
| `gobpf.Program.Attach` | the tcx direction of sched_cls ("ingress" / "egress") |
| `gobpf.Program.ExtTarget` | ExtTarget is the name of the program an ext program replaces into (directive `//gobpf:ext <program> <function>`). |
| `gobpf.Program.Func` |  |
| `gobpf.Program.IterMap` | IterMap is the name of the map an iter program iterates over (directive `//gobpf:iter bpf_map_elem <map>`). |
| `gobpf.Program.Kind` | "xdp" / "sched_cls" |
| `gobpf.Program.PerfMaps` | PerfMaps are the perf_event_arrays the program outputs to (AttachFentry confirms an open reader exists). |
| `gobpf.Program.Symbol` |  |
| `gobpf.Program.USDTSpec` | USDTSpec is the max_entries of a usdt program's compiler spec map `__ebpf_usdt_spec_<Symbol>` (the schema's max_points). |
| `gobpf.Reader` | Reader is the user-space reader of a ring buffer (bpf.RingBuf[V]). |
| `gobpf.Reader.Close` | Close closes the reader (a second call does nothing). |
| `gobpf.Reader.Read` | Read waits for and reads the next event (os.ErrDeadlineExceeded at the SetDeadline deadline). |
| `gobpf.Reader.SetDeadline` | SetDeadline sets the deadline for Read (the zero value means no deadline). |
| `gobpf.Record` | Record is a record layout the generated file registers (bpf-mlir go/layout's Record and the user's Go type). |
| `gobpf.Record.New` |  |
| `gobpf.Record.Size` |  |
| `gobpf.Record.Symbol` |  |
| `gobpf.Record.Type` |  |
| `gobpf.Register` | Register is called from the generated file's init (the user does not call it). |
| `gobpf.RequirementsError` | RequirementsError means the embedded ELF's requirements section cannot be read (an alias of the bindrt type since bpf-mlir v0.4.0). |
| `gobpf.ReuseportLink` | ReuseportLink is an sk_reuseport attach (SO_ATTACH_REUSEPORT_EBPF — attached to a socket's SO_REUSEPORT group). |
| `gobpf.ReuseportLink.Close` | Close detaches the program from the group (through the attached socket's fd — ENOENT if the group has no program). |
| `gobpf.RunSyscall` | RunSyscall runs a syscall program (a function value) once with BPF_PROG_TEST_RUN (it is not attached). |
| `gobpf.SchemaMismatchError` | SchemaMismatchError means the SHA-256 of the schema that built the ELF differs from the generated file's (a build that did not rerun go generate — an alias of the bindrt type). |
| `gobpf.Seg6LocalRoute` | Seg6LocalRoute is a seg6local route in a test netns. |
| `gobpf.Seg6LocalRoute.Close` | Close deletes the route (RTM_DELROUTE in the same netns — with the guard). |
| `gobpf.ShortRecordError` | ShortRecordError is the generated Decode's error for a short input. |
| `gobpf.SocketFilterLink` | SocketFilterLink is a socket_filter attach (SO_ATTACH_BPF). |
| `gobpf.SocketFilterLink.Close` | Close detaches the program from the socket. |
| `gobpf.TCPCongestionAvailable` | TCPCongestionAvailable reports whether name is in the list of registered TCP congestion control names. |
| `gobpf.TailSlot` | TailSlot is the declaration of one prog_array slot (written by the generated file — Pos is the position of the bpf.TailSlot call). |
| `gobpf.TailSlot.Map` |  |
| `gobpf.TailSlot.Pos` |  |
| `gobpf.TailSlot.Program` |  |
| `gobpf.TailSlot.Slot` |  |
| `gobpf.TailSlotError` | TailSlotError is a mismatch between the generated file's tail call slot declarations and the embedded ELF's tailslot rows (it wraps bindrt.CheckTailSlots' error). |
| `gobpf.TailSlotError.Decls` | the generated file's declarations (with Go positions) |
| `gobpf.TailSlotError.Err` | bindrt.CheckTailSlots' error |
| `gobpf.TailSlotError.Error` |  |
| `gobpf.TailSlotError.Unwrap` |  |
| `gobpf.TargetError` | TargetError is a requirement mismatch that stops the load (BlocksLoad of requirements.Unmet). |
| `gobpf.UprobeMultiLink` | UprobeMultiLink is the link from AttachUprobeMulti and whether its attach target could be checked with the kernel's link info. |
| `gobpf.UprobeMultiLink.Verified` | Verified reports whether, after attaching, the link info's offsets, cookies and pid were confirmed to match the passed values. |
| `gobpf.UprobeTarget` | UprobeTarget is AttachUprobe's run-time input (the binary is the fd passed to Load with WithUprobeTarget). |
| `gobpf.UprobeTarget.PID` | PID is the process to attach to (0 means every process). |
| `gobpf.UserRingWriter` | UserRingWriter is the user-space writer of a user ring buffer (bpf.UserRingBuf[V]). |
| `gobpf.UserRingWriter.Close` | Close unmaps the ring (later calls do nothing). |
| `gobpf.UserRingWriter.Write` | Write writes v as one sample (the record's little-endian bytes). |
| `gobpf.Version` | Version is the go-bpf-mlir version. |
| `gobpf.WithUprobeTarget` | WithUprobeTarget passes to Load the **run-time path** of the target binary of the uprobe (and uretprobe) program fn. |
