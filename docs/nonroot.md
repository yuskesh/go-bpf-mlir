# Loading and attaching without root (gobpf)

The permissions a **non-root user** (uid ≠ 0, a process with only the capabilities it needs) requires to load and attach a gobpf program, and the known refusals.
Every statement below was measured on a real kernel; the "Measured on" column names the kernels, and anything that was not measured says so.
The method follows bpf-mlir's non-root document (`docs/nonroot.md` in bpf-mlir): root prepares the netns and veth, and `setpriv` drops the program to uid 1000 with a given capability set.
The kernels are 7.1.8 (host) and 6.12.111 / 6.6.157 (in a VM).

## Required capabilities — quick reference

| What the program uses | Required capabilities (uid 1000) | Measured on |
|---|---|---|
| maps (array / hash / lru_hash / **per-CPU maps**), records, ring buffer, AddOrInit, bounded loops ((U) unrolling), variable index into a record array (ref.index), packet windows at constant offsets | **CAP_BPF + CAP_NET_ADMIN** | 7.1.8, 6.12.111, 6.6.157 |
| **packet windows at a variable offset** (the off of `ctx.Check(off, n)` is not a constant — for example L4 after the IHL) | **+ CAP_PERFMON** (without it the verifier refuses the load with `pointer arithmetic with it prohibited for !root`) | 7.1.8, 6.12.111, 6.6.157 |
| **fexit programs** (`//gobpf:fexit <fn> nargs=<N>` — the return value) | **CAP_BPF + CAP_PERFMON** (same as fentry — with {CAP_BPF, CAP_NET_ADMIN} the target check's probe gets EPERM) | 7.1.8, 6.12.111, 6.6.157 |
| **fentry programs** (`//gobpf:fentry <fn>` — tracing) | **CAP_BPF + CAP_PERFMON** (CAP_NET_ADMIN is not needed. With {CAP_BPF, CAP_NET_ADMIN} the target check's probe (the tracing program type) gets EPERM — the gobpf hint points to CAP_PERFMON). An object that also holds XDP / tcx programs needs {CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON} | 7.1.8, 6.12.111, 6.6.157 |
| **uprobe programs** (`//gobpf:uprobe` — attached through perf_uprobe) | **CAP_SYS_ADMIN** (with combinations of CAP_BPF / CAP_PERFMON / CAP_NET_ADMIN the attach gets EPERM). With {CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN} the uprobe tests, greetwatch and ustack pass on all three kernels; CAP_SYS_ADMIN alone is enough for the uprobe tests on 7.1.8 | 7.1.8, 6.12.111, 6.6.157 (CAP_SYS_ADMIN alone: 7.1.8) |
| **raw_tp, kretprobe and uretprobe programs** (`//gobpf:raw_tp`, `//gobpf:kretprobe`, `//gobpf:uretprobe`) | raw_tp and kretprobe: **CAP_BPF + CAP_PERFMON**; uretprobe: **+ CAP_SYS_ADMIN** (same as uprobe — with {CAP_BPF, CAP_PERFMON} creating the perf_uprobe for the attach is refused). **tracepoint programs** (`//gobpf:tracepoint`) are **root only** — the tpfield check in Load reads the tracefs format, which a non-root loader cannot read (Unknown, so the whole Load stops — the other programs in the same object too; the same for `bpf.UserStr` user string fields and `[N]byte` array fields) | 7.1.8 |
| **socket and cgroup programs** (`socket_filter`, `cgroup_skb`, `cgroup_sock`, `cgroup_sock_addr`, `sock_ops`) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (the cgroup_sock_addr program type) gets EPERM). Attaching to a cgroup directory needs permission to open the directory — attach and the socket_filter differential test pass when root creates a test-only directory and chowns it to uid 1000. The differential test that moves a child process into the cgroup is root only (it needs cgroup delegation) | 7.1.8 |
| **local storage maps** (`bpf.TaskStorage`, `SKStorage` from fentry) | **CAP_BPF + CAP_PERFMON** (same as fentry — with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (the tracing program type) gets EPERM) | 7.1.8 |
| **reads behind a kprobe pointer argument** (`bpf.KprobeRead`) | **CAP_BPF + CAP_PERFMON** (same as kprobe — with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM) | 7.1.8 |
| **fentry integer arguments** (`bpf.FentryArgInt`) | **CAP_BPF + CAP_PERFMON** (same as fentry). The type check (farg) in CheckTarget also gets EPERM from the program type probe without root — Load with root or with the capability set | 7.1.8 |
| **periodic timers** (Start of its own timer inside the callback) | **CAP_BPF + CAP_NET_ADMIN** (the xdp load — CAP_SYS_ADMIN also works on 7.1.8; the timer helper needs CAP_BPF. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM; with no capabilities, memlock) — the same shape as a one-shot timer | 7.1.8 |
| **bpf() from a syscall program** (`bpf.SysBpf` / `bpf.SysClose`) | **CAP_BPF + CAP_PERFMON** (the helper bpf_sys_bpf — CAP_SYS_ADMIN also works on 7.1.8; with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} it stops before Load with "needs helper sys_bpf (166)"; with no capabilities, memlock). **map_get_fd_by_id needs CAP_SYS_ADMIN** (without it −EPERM — before the ID is looked up) | 7.1.8 |
| **sk_lookup socket selection** (`SockMap.Assign` / `SockHash.Assign`) | **CAP_BPF + CAP_NET_ADMIN** (creating the sockmap / sockhash — CAP_SYS_ADMIN also works on 7.1.8; the sk_lookup load needs CAP_BPF. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (SockHash) gets EPERM; with no capabilities, memlock). Test run only (attaching to a netns was measured as root only) | 7.1.8 |
| **kernel char * strings** (`RingBuf.OutputKernelStr` from fentry) | **CAP_BPF + CAP_PERFMON** (fentry and the helper probe_read_kernel_str — with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Tracing) gets EPERM; with no capabilities, memlock) | 7.1.8 |
| **lsm and lsm.s programs** (`//gobpf:lsm`, `//gobpf:lsm_s`) | **CAP_BPF + CAP_PERFMON** (load, attach and deny — with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (LSM) gets EPERM). Reading by link ID (BPF_LINK_GET_FD_BY_ID) needs CAP_SYS_ADMIN. The kernel needs BPF LSM | 7.1.8 |
| **perf_event programs** (`bpf.PerfEventContext`, `gobpf.AttachPerfEvent`) | **CAP_BPF + CAP_PERFMON** (with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (PerfEvent) gets EPERM) and permission to open the event — with perf_event_paranoid 2, an exclude_kernel event on its own thread | 7.1.8 |
| **maps without keys** (`bpf.Queue`, `Stack`, `BloomFilter` from xdp) | **CAP_BPF** to create the map, **CAP_NET_ADMIN or CAP_SYS_ADMIN** to load and test-run the xdp program (with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM) | 7.1.8 |
| **map-in-map** (`bpf.ArrayOfMaps`, `HashOfMaps` from xdp) | creating the outer map and array / hash inner maps needs no privileged type (an lru_hash inner map needs CAP_BPF); **CAP_NET_ADMIN or CAP_SYS_ADMIN** to load and test-run the xdp program — the same capability sets as maps without keys (with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM) | 7.1.8 |
| **XDP redirect maps** (`bpf.CPUMap`, `DevMapHash`, `XSKMap`) | **CAP_BPF + CAP_NET_ADMIN or CAP_SYS_ADMIN** for load and entry Set (creating a CPUMAP needs CAP_BPF; DEVMAP_HASH, XSKMAP and the xdp load need CAP_NET_ADMIN — with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM). Real packets, AF_XDP sockets (CAP_NET_RAW) and netns creation were not measured without root | 7.1.8 (load and Set only) |
| **ksyscall programs** (`//gobpf:ksyscall`) | **Load stops without root** — the argument type check (sysarg) reads the tracefs `sys_enter_<name>` format, which a non-root loader cannot read (it stops as Unknown even with {CAP_BPF, CAP_PERFMON} — the same for `bpf.KsyscallStr` user string arguments). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM. gobpf's loader declaration covers ksyscall attach (the ksyscall_attach prefix) | 7.1.8 |
| **user strings from tracepoint fields and ksyscall arguments** (a `bpf.UserStr` event field, `bpf.KsyscallStr`, read with `RingBuf.OutputStr` / `OutputStrOrDiscard`; the same for arrays — a `bpf.UserStrArray` field, `bpf.KsyscallStrArray`, the strarray rows) | **root only** — with {CAP_BPF, CAP_PERFMON} (also with CAP_NET_ADMIN or CAP_SYS_ADMIN added) Load stops with the requirements Unknown (the tpfield and sysarg strptr rows need the tracefs `sys_enter_<name>` format, which a non-root loader cannot read). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM; with no capabilities, memlock | 7.1.8 |
| **kprobe_multi programs** (`//gobpf:kprobe_multi`) | **CAP_BPF + CAP_PERFMON** (same as kprobe — with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM). Creating the kprobe.multi link needs no further capability | 7.1.8 |
| **uprobe_multi programs** (`//gobpf:uprobe_multi`) | **CAP_BPF + CAP_PERFMON** (the CAP_SYS_ADMIN of a single uprobe is not needed — the uprobe.multi link does not go through perf_event_open, and bpf_uprobe_multi_link_attach has no capability check. With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM; with none, memlock) | 7.1.8 |
| **usdt programs** (`//gobpf:usdt`) | **CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN** (same as a single uprobe — the gobpf.AttachUSDT glue is a perf uprobe: {CAP_BPF, CAP_PERFMON} and {CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON} get `creating perf_uprobe PMU: … opening perf event: permission denied`; with {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM; with none, memlock) | 7.1.8 |
| **sk_skb programs and sockmap / sockhash** (`//gobpf:sk_skb`) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN in place of CAP_NET_ADMIN — the kernel's bpf_ns_capable): with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (loading an SkSKB program) gets EPERM; with none, memlock. The PROG_ATTACH attach needs no further capability | 7.1.8 |
| **sk_msg and sock_ops insertion** (`//gobpf:sk_msg`) | **load and attach: CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN): with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (loading an SkMsg program) gets EPERM; with none, memlock. **The differential test (moving a child process into the test cgroup) is root only** — it needs write permission on the ancestors in the cgroup tree (same as socket and cgroup programs) | 7.1.8 (load and attach only) |
| **sched_act program test run** (`bpf.TCActContext`) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN): with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (loading a SchedACT program) gets EPERM; with none, memlock. The test run needs no further capability (there is no attach) | 7.1.8 |
| **ring buffer reservation** (`RingBuf.Reserve`, xdp test run) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — the xdp load and test run): with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (loading an XDP program) gets EPERM; with none, memlock. Reserving needs no further capability | 7.1.8 |
| **back-edge loops (B)** (`//gobpf:loop backedge`, xdp test run) | **7.1.8 accepts with CAP_BPF + CAP_NET_ADMIN** (with bpf-mlir's current compiler) — both a constant 64-iteration body without branches on unknown values and a body with a packet bound and break. **With the earlier compiler of bpf-mlir v1.11.0, the packet-bound body also needed CAP_PERFMON** (without it `The sequence of 8193 jumps is too complex.` — the verifier's speculative paths without CAP_PERFMON); bpf-mlir v1.13.0's default `--tune-backedge-spill` made it accepted. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON}, the target check's probe; with none, memlock. **6.12 and 6.6 refuse (B) for a loader without CAP_PERFMON** (measured in bpf-mlir; the spill does not help on 6.x; not measured with gobpf on 6.x) | 7.1.8 (current compiler and bpf-mlir v1.11.0) |
| **bpf_loop callback loops (H)** (`//gobpf:loop callback`, xdp test run) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN) — CAP_PERFMON is not needed (bpf_loop is a CAP_BPF helper). Both the constant 64-iteration body and the bound-and-break body that (B) refused on 7.1.8 are accepted. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON}, the target check's probe; with none, memlock | 7.1.8 (7 capability sets); 6.12.111 and 6.6.157 ({CAP_BPF, CAP_NET_ADMIN} only) |
| **lsm_cgroup programs** (`//gobpf:lsm_cgroup`, gobpf.AttachCgroup) | **CAP_BPF + CAP_PERFMON** (load — LSM in the kernel's is_perfmon_prog_type). Attach and detach (BPF_LINK_CREATE on the cgroup fd, closing the link) need no further capability (7.1.8 source and measurement), plus permission to open the cgroup directory. With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (LSM) gets EPERM; with none, memlock | 7.1.8 |
| **fsession programs** (`//gobpf:fsession`, gobpf.AttachFsession) | **CAP_BPF + CAP_PERFMON** (load — TRACING in the kernel's is_perfmon_prog_type). Attach (bpf_tracing_prog_attach), test run and reading the link info need no further capability (7.1.8 source and measurement). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Tracing) gets EPERM; with none, memlock. The kernel needs fsession (7.1.8), and cilium/ebpf needs fsession support (see the README) | 7.1.8 |
| **iter programs** (`//gobpf:iter bpf_map_elem`, gobpf.AttachIter and reading Open) | **CAP_BPF + CAP_PERFMON** (load — TRACING). The iterator link, fd and read need no further capability (7.1.8 source and measurement). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Tracing) gets EPERM; with none, memlock | 7.1.8 |
| **cgroup_device programs** (`bpf.CgroupDeviceContext`, gobpf.AttachCgroup) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — is_net_admin_prog_type at load); attach and detach need no further capability. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (CGroupDevice) gets EPERM; with none, memlock | 7.1.8 |
| **cgroup_sysctl programs** (`bpf.CgroupSysctlContext`, gobpf.AttachCgroup) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — is_net_admin_prog_type at load); attach and detach need no further capability. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (CGroupSysctl) gets EPERM; with none, memlock. The differential test (a child in a new netns) is root only — measured without root: load, attach and detach | 7.1.8 (load, attach, detach) |
| **cgroup_sockopt programs** (`bpf.CgroupSetsockoptContext` / `CgroupGetsockoptContext`, gobpf.AttachCgroup) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — is_net_admin_prog_type at load); attach and detach need no further capability. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (CGroupSockopt) gets EPERM; with none, memlock | 7.1.8 |
| **sk_lookup programs** (`bpf.SkLookupContext`, gobpf.AttachNetNs) | **CAP_BPF** to load (SK_LOOKUP is not in is_net_admin_prog_type). With none, memlock. The netns link was not measured without root (attaching to a netns was tested as root only) | 7.1.8 (load) |
| **sk_reuseport programs and reuseport_sockarray** (`bpf.SkReuseportContext`, `bpf.ReuseportSockArray`, gobpf.AttachReuseport) | **CAP_BPF only** (SK_REUSEPORT is outside is_net_admin_prog_type — the kernel's comment says "equivalent to SOCKET_FILTER"); SO_ATTACH / DETACH_REUSEPORT_BPF and the sockarray Set need no further capability — with {CAP_BPF} or more, all six capability sets pass the 9 steps of group selection, drop, detach and close. With none, memlock. Observing the ID disappear after close needs CAP_SYS_ADMIN (ID to fd) — the other sets skip that step with EPERM | 7.1.8 |
| **flow_dissector programs** (`bpf.FlowDissectorContext`, gobpf.AttachNetNs) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN — is_net_admin_prog_type at load) for load and test run — **with packet windows at constant offsets only, CAP_PERFMON is not needed** (a variable offset needs CAP_PERFMON too). With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (FlowDissector) gets EPERM; with none, memlock. The netns link was tested as root only | 7.1.8 (load and test run) |
| **netfilter programs** (`bpf.NetfilterContext`, gobpf.AttachNetfilter) | **CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON** (or CAP_SYS_ADMIN) for load and test run — reading behind state / skb needs CAP_PERFMON in the verifier ({CAP_BPF, CAP_NET_ADMIN} gets `'struct nf_hook_state' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN`); with {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (Netfilter) gets EPERM; with none, memlock. The link was tested as root only (without root, gobpf.AttachNetfilter cannot read /proc/1/ns/net and does not attach) | 7.1.8 (load and test run) |
| **lwt_in / lwt_out / lwt_xmit programs** (`bpf.LWTInContext` and others, gobpf.AttachLWTRoute) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN) for load and test run (windows at constant offsets). With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (LWTIn) gets EPERM; with none, memlock. Adding the route was tested as root only (without root, gobpf.AttachLWTRoute cannot read /proc/1/ns/net and does not send — setns also needs CAP_SYS_ADMIN) | 7.1.8 (load and test run) |
| **lwt_seg6local programs** (`bpf.Seg6LocalContext`, gobpf.AttachSeg6Local) | **CAP_BPF + CAP_NET_ADMIN** (or CAP_SYS_ADMIN) to load (there is no test run). With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (LWTSeg6Local) gets EPERM; with none, memlock. Adding the route was tested as root only (without root, gobpf.AttachSeg6Local cannot read /proc/1/ns/net and does not send) | 7.1.8 (load only) |
| **fmod_ret programs** (`//gobpf:fmod_ret`, gobpf.AttachFmodRet) | **CAP_BPF + CAP_PERFMON** (load — TRACING is in is_perfmon_prog_type, same as fentry / fsession). Attach and the tracing test run need no further capability (measured on 7.1.8 — bpf_modify_return_test). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Tracing) gets EPERM; with none, memlock | 7.1.8 (load, attach, test run) |
| **raw_tp_writable programs** (`//gobpf:raw_tp_writable`, gobpf.AttachRawTPWritable) | **CAP_BPF + CAP_PERFMON** (load — RAW_TRACEPOINT_WRITABLE is in is_perfmon_prog_type). Attach (opening the raw tracepoint) and writing the buffer need no further capability (measured on 7.1.8 — bpf_test_finish, triggered by a fentry tracing test run). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (RawTracepointWritable) gets EPERM; with none, memlock | 7.1.8 (load, attach, test-run trigger) |
| **kprobe_session programs** (`//gobpf:kprobe_session`, gobpf.AttachKprobeSession) | **CAP_BPF + CAP_PERFMON** (load — same as kprobe). Creating the kprobe.multi Session link needs no further capability (measured on 7.1.8 — bpf_fentry_test1). With {CAP_BPF} or {CAP_BPF, CAP_NET_ADMIN} the target check's probe (Kprobe) gets EPERM; with none, memlock. 7.1.8 only (on 6.12 / 6.6 it stops before load) | 7.1.8 (load, attach, test-run trigger) |
| **syscall programs** (`bpf.SyscallContext`, gobpf.RunSyscall) | **CAP_BPF only** (load and test run — SYSCALL is outside is_net_admin_prog_type / is_perfmon_prog_type, and it is not attached). With none, memlock | 7.1.8 (load and test run) |
| **user_ringbuf maps and drain** (`bpf.UserRingBuf`, gobpf.NewUserRingWriter) | creating the map and the helper user_ringbuf_drain need **CAP_BPF**, plus the capability of the draining program's type (**CAP_NET_ADMIN** for xdp, as measured). The user-space writer's mmap needs no further capability. With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM; with none, memlock | 7.1.8 (load, write, xdp test run) |
| **cgroup_array maps and TaskUnder / SkbUnder** (`bpf.CgroupArray`) | **CAP_BPF** for the map and helpers, plus the program types' capabilities (as measured, **CAP_PERFMON** for fentry and **CAP_NET_ADMIN** for tc — a package with both needs both). With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (SchedCLS) gets EPERM, with {CAP_BPF, CAP_NET_ADMIN} the probe (Tracing) gets EPERM; with none, memlock. Creating the test cgroup and moving a child into it need permission on the cgroup directory (measured without root: a test run in its own process only) | 7.1.8 (load, test run in its own process) |
| **struct_ops (tcp_congestion_ops — `bpf.TCPCongestionOps`)** | **CAP_BPF** for the map and **CAP_PERFMON** for the programs; registration (creating the link) has no capability check. **A socket that selects the algorithm by name needs CAP_NET_ADMIN** (flags 0 — no TCP_CONG_NON_RESTRICTED). With {CAP_BPF} the target check's probe (StructOps) gets EPERM; {CAP_BPF, CAP_PERFMON} gets through registration and setsockopt TCP_CONGESTION gets EPERM. **Measured only inside a VM** (skipped on the host for the host's protection) | 6.12.111 in a VM (3 capability sets) |
| **ext (freplace — `//gobpf:ext`)** | **CAP_BPF + CAP_PERFMON** to load the ext program, plus the capability of the replaced program's kind (**CAP_NET_ADMIN** or CAP_SYS_ADMIN for xdp, as measured). **CAP_SYS_ADMIN is not needed** — the replaced program's BTF comes from cilium's cache of the program it loaded itself (it does not take the kernel's BPF_BTF_GET_FD_BY_ID path that needs CAP_SYS_ADMIN — this was not what we predicted). With {CAP_BPF} or {CAP_BPF, CAP_PERFMON} the target check's probe (XDP) gets EPERM, with {CAP_BPF, CAP_NET_ADMIN} the probe (Extension — CAP_PERFMON) gets EPERM; with none, memlock | 7.1.8 (3 steps — the test's own programs only) |
| (note) **Can CAP_SYS_ADMIN replace CAP_NET_ADMIN?** | On 7.1.8 and 6.12.111 it does for xdp / tcx loads and map creation (with {CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN} all 57 items pass — the kernel's `bpf_net_capable` takes NET_ADMIN or SYS_ADMIN). **On 6.6.157, creating a DevMap checks CAP_NET_ADMIN only** (`capable(CAP_NET_ADMIN)` in syscall.c) — redir and xdpfwd fail with the CAP_SYS_ADMIN set | 7.1.8, 6.12.111, 6.6.157 |

## The full matrix (the same on all three kernels unless noted)

The matrix runs the test binaries and the examples' `-selftest` (load, test run, maps, the ring buffer reader, iterate) as uid 1000 with each capability set, on 7.1.8 (host)
and 6.12.111 / 6.6.157 (VM), and records the `Cap` lines of `/proc/self/status` for each set.
Each row was measured with the bpf-mlir compiler of the time it was added; when the compiler or its verdict version changed, the matrix was run again and **the rows in common gave
the same results on all three kernels** (the last full rerun had 30 items × 6 capability sets per kernel; rows added later were each checked against the earlier rows with no difference).
The target check reported **no Unknown and no BTF rewrite mismatch** for any item that a non-root loader got as far as loading; the only Unmet results were the intended negative examples
(fentrybad, fexitbad, fexitunchecked's attach) and the tracing ELFs' probe EPERM under {CAP_BPF, CAP_NET_ADMIN} (CAP_PERFMON is needed — known).

| Item (what it uses) | root | none | CAP_BPF | CAP_BPF + CAP_NET_ADMIN | + CAP_PERFMON | Notes |
|---|---|---|---|---|---|---|
| xdpcount (array AtomicAdd) | ✓ | ✗ memlock | ✗ probe | ✓ | ✓ | |
| ethercount (packet windows at constant offsets, subprograms) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| addinit (hash, record keys, AddOrInit) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| ev (ring buffer Output and reader, CountDropsIn, **bool in Output**) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| hash (Insert / Replace / Update / Delete status, Iterate, lru_hash) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| **opsfill** (LRUHash / PerCPUHash / LRUPerCPUHash, PerCPUArray.Update, egress Redirect, ingress RedirectIf) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels |
| loops (bounded loops — (U) unrolling) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| idx (variable index into a record array — ref.index) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| **idxfit** (five ref.index shapes — the [5] warning at the record's end, [8], headroom, after a range check, the same index into two maps (atwo)) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels, with bpf-mlir's masked index (M1) |
| rec (reading and writing value fields of a record map) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| percpu (per-CPU array / hash / lru hash — the current CPU's slot, per-CPU reads and writes) | ✓ | — | — | ✓ | ✓ | only root and {CAP_BPF, CAP_NET_ADMIN} measured |
| tc (sched_cls — tcx ingress / egress verdicts and redirect in test runs, a real tcx attach on lo) | ✓ | — | — | ✓ | ✓ | root and {CAP_BPF, CAP_NET_ADMIN} on all three kernels — **the tcx attach too, on 6.12 / 6.6** |
| tccount (three programs, XDP and tcx ingress / egress, share a map — windows at constant offsets, XDP and tcx attach on veth) | ✓ | — | — | ✓ | — | selftest on all three kernels and the host veth attach with {CAP_BPF, CAP_NET_ADMIN} |
| pktkind (the same packet read from XDP and sched_cls — windows at a variable offset) | ✓ | — | — | ✗ `!root` | ✓ | all three kernels; {CAP_BPF, CAP_NET_ADMIN} refuses the variable-offset addition in both kinds (7.1.8 / 6.6 report xdpRead first, 6.12 reports tcRead first) |
| fatomic (`bpf.AtomicAdd` on a record field of a shared map — ref.field.atomic_add, run on several CPUs at once) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels |
| **syscount** / fentry (fentry programs — do_sys_poll and bpf_fentry_test1, hash AddOrInit, the comm in a ring buffer) | ✓ | — | — | **✗ probe** (`detect support for Tracing … operation not permitted`) | — (**✓ with {CAP_BPF, CAP_PERFMON}** — CAP_NET_ADMIN is not needed) | all three kernels. The capability sets of this row differ from the other rows — fentry was measured with {CAP_BPF, CAP_PERFMON} |
| **idxdef** (the **constant default of an index read from a map reaches** a shape-A ref.index **unconditionally**) | ✓ | ✗ | ✗ | **✓ on 7.1.8, ✗ `!root` on 6.12 / 6.6** (`tried to add from different maps, paths or scalars`) | ✓ | reproduces bpf-mlir's analysis with gobpf's generated output |
| ops (integer operators, subprograms) | ✓ | ✗ | ✗ | ✓ | ✓ | |
| **globals** / **globalsopt** / **portcount** (global variables — Config in .rodata, Global in .bss) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels |
| **globalsmulti** (several globals in the same section) / **lpm** (lpm_trie Lookup and Match) / **verdict** (conditional verdicts — verdict.if, XDP and tcx) / **ipdeny** (XDP drop by lpm_trie longest match) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels. {CAP_BPF, CAP_PERFMON} is ✗ — XDP / tcx test runs need CAP_NET_ADMIN. ipdeny's real veth attach also gives RESULT ok with {CAP_BPF, CAP_NET_ADMIN} (7.1.8) |
| **kprobe** (kprobe argument registers — nfds of do_sys_poll, dfd of do_sys_openat2) / **openwatch** (kprobe example — opens per tgid) | ✓ | ✗ | ✗ | **✗** (probe EPERM — CAP_PERFMON is needed) | ✓ | all three kernels. **{CAP_BPF, CAP_PERFMON} is ✓** (same as fentry). A non-root kprobe attach goes through perf_event_open — kernel.perf_event_paranoid was 2 on all three kernels; stricter values were not tried |
| **redir** (the devmap redirect_map return value) / **xdpfwd** (devmap redirect_map example) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels. {CAP_BPF, CAP_PERFMON} is ✗ — XDP test runs need CAP_NET_ADMIN. Real forwarding between two veth pairs also gives RESULT ok with {CAP_BPF, CAP_NET_ADMIN} (7.1.8) |
| **uprobe** (uprobe arguments and user strings — C and cgo fixtures) / **greetwatch** (uprobe example) | ✓ | ✗ | ✗ | ✗ | ✗ | all three kernels. **None of the matrix's six sets includes CAP_SYS_ADMIN, so only root is ✓** — creating the uprobe perf event needs CAP_SYS_ADMIN. **{CAP_SYS_ADMIN, CAP_BPF} (uid 1000) is ✓** — the differential tests (all three kernels) and greetwatch's selftest (7.1.8); {CAP_BPF, CAP_PERFMON} gets "opening perf event: permission denied" at attach |
| **stackperf** (fentry stack traces and perf events — the skip model, refusing an attach before the reader, 2 CPUs, the −ENOENT control, overflow) / **pollstack** (do_sys_poll stack ids through perf — example) | ✓ | ✗ | ✗ | **✗ probe** (`detect support for Tracing … operation not permitted` — same as fentry) | ✓ | all three kernels. **{CAP_BPF, CAP_PERFMON} is also ✓** (same as fentry — CAP_NET_ADMIN is not needed). perf_event_paranoid was 2 on all three kernels. Without root, /proc/kallsyms shows addresses as 0, so stacks cannot be named (pollstack prints addresses) |
| **rewrite** / **xdpdecap** (XDP packet rewriting — Window Set, AdjustHead / AdjustTail, XDP_TX) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels |
| **tail** / tailparse (prog_array slots and tail calls — variable slot index, TailCallIf, the chain limit, re-reading with ctx.Check in the fallback) | ✓ | ✗ | ✗ | ✓ | ✓ | all three kernels. {CAP_BPF, CAP_PERFMON} is ✗ probe |
| **pkt** (packet windows — **including a variable offset**) | ✓ | ✗ | ✗ | **✗ `!root`** | ✓ | |
| **voff** (variable offset — the IHL) | ✓ | ✗ | ✗ | **✗ `!root`** | ✓ | |
| **loopwalk** / **tcpopts** (ctx.Check inside a bounded loop — a TCP options walk) | ✓ | ✗ | ✗ | **✗ `!root`** | ✓ | all three kernels |
| **flowsample** (all of the above + a variable offset) | ✓ | ✗ | ✗ | **✗ `!root`** | ✓ | |

Where it stopped (the same on all three kernels):

- **none**: the first `rlimit.RemoveMemlock` fails with `operation not permitted` (before the embedded program is loaded)
- **CAP_BPF only**: the target check of the checked `gobpf.Load` (the livecaps probe — a load that detects the XDP program type) fails with `operation not permitted` and returns
  `*PrecheckError` — "target precheck failed before loading the embedded program: detect support for XDP: …" (the same as bpf-mlir). The embedded program is not loaded
- **CAP_BPF + CAP_NET_ADMIN with a variable offset**: loading the embedded program, the verifier reports `R2 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root`
  (a variable addition to the packet pointer)

### Notes on the matrix

- **Packet rewriting** (rewrite, xdpdecap — Window Set, AdjustHead / AdjustTail, XDP_TX with constant indexes) **passes with {CAP_BPF, CAP_NET_ADMIN}**; CAP_PERFMON is not needed
  (there is no variable packet offset; AdjustHead's runtime delta is a map value, not an addition to the packet pointer). None, CAP_BPF and {CAP_BPF, CAP_PERFMON} stop like the other XDP items.
- **Packet walks inside a loop** (loopwalk, tcpopts — `ctx.Check(off, n)` in a bounded loop where off advances by the option length) **are refused by the verifier with
  {CAP_BPF, CAP_NET_ADMIN}** (`pointer arithmetic with it prohibited for !root` — a variable offset, the same as bpf-mlir's C oracle) and **pass with + CAP_PERFMON and as root**
  (all three kernels). The refusal names the Go line (`the verifier rejected program WalkSYN at main.go:69` — the Check inside the loop).
- **Tail calls** (tail, tailparse) need the same capability sets as the other XDP items — they pass as root, with {CAP_BPF, CAP_NET_ADMIN} and with {CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON},
  and stop with none (memlock), CAP_BPF and {CAP_BPF, CAP_PERFMON} (the XDP probe). The prog_array, the tail_call helper and a variable slot index add no required capability (all three kernels).
- **line_info** (BTF line info in the ELF) does not change the verifier's decisions. With **{CAP_BPF, CAP_PERFMON}**, only the fentry items (fentry, syscount) pass; the XDP / tcx items
  stop at the target check's probe (CAP_NET_ADMIN is needed). The fentry items pass as root, with {CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON} and with {CAP_BPF, CAP_PERFMON}, and stop with
  {CAP_BPF, CAP_NET_ADMIN} (all three kernels). The refusal names the Go line of the refusal (`the verifier rejected program … at <file>.go:<line>`).
- With {CAP_BPF, CAP_NET_ADMIN}, only the four variable-offset items (flowsample, voff, pkt, pktkind) are refused; with + CAP_PERFMON all pass. fatomic passes with {CAP_BPF, CAP_NET_ADMIN}.

### A variable index into a record array (ref.index) and CAP_PERFMON

A non-root refusal depends not on where the index comes from (a map value or not) but on **whether a constant index and an unknown index reach the same pointer addition along different
paths** (the verifier distinguishes scalars per path). In a test program where the index read from a map has a default value (0) on a path where the operation selector also takes its
default and the indexed block is not entered, 6.x accepts a non-root loader. In a test program where the default value reaches `if i < uint32(len(p.Arr))` unconditionally, 6.12 / 6.6
refuse a non-root loader (7.1.8 accepts) — this is the **idxdef** row, and bpf-mlir's masked index (M1) does not resolve it (the GB024 warning).
**How to write it so that it passes on all three kernels without CAP_PERFMON**: do not let the index's default value reach the indexed block (use the index inside the checked branch of the
Lookup that reads it, or take the default-value path out with another condition), and use (U) unrolling (a constant) for a loop variable index. The frontend does not check this shape
(the gobpf hint points to CAP_PERFMON).

**bpf-mlir's masked index (M1 — the mask on the true edge of the ref.index check and the re-check)**: the shape that uses the same index into the record arrays of two map lookups
(idxfit's atwo) is refused on 6.12 / 6.6 with {CAP_BPF, CAP_NET_ADMIN} when compiled without M1 (`--tune-mask-checked-index=false`) with
`math between map_value pointer and register with unbounded min value is not allowed`, and the ELF built with the default (M1) is accepted on all three kernels with three capability sets.
A ref.index after a range check (twocmp — `if i < 8 { if i < len … }`) is accepted even without M1 — it is not a shape that M1 helps.

### The 6.6 kernel and the number of unrolled walk iterations

Measured in bpf-mlir with the shape of gobpf's TCP options walk (with an i8 exit mark, as root; the values match the Go reference in every frame): the 7.1.8 / 6.12.111 verifiers keep
a constant state per iteration and the processed count grows in proportion to N (about 4.5 thousand at N = 8), but **6.6.157 adds states per iteration: 9190 at N = 8 and
561,836 at N = 28** (over half of the 1M limit). For a walk that targets 6.6, **keep N at 16 or below** (examples/tcpopts uses N = 16 — accepted in the non-root matrix on all three kernels),
and check the load on 6.6 when you make it larger. Whether CAP_PERFMON is needed does not depend on N.

| N (unrolled iterations) | 7.1.8 | 6.12.111 | 6.6.157 |
|---|---|---|---|
| 8 | 4503 | 4606 | 9190 |
| 16 | 10891 | 11328 | **69177** |
| 24 | 18656 | 18656 | 47687 |
| 28 | 25622 | 25622 | **561836** (56% of 1M) |

(6.6 is not monotonic in N.)

## A real attach on the host (7.1.8)

Root sets up only the netns, veth and capture; the program runs as uid 1000:

| program | capabilities (uid 1000) | result |
|---|---|---|
| xdpcount | CAP_BPF + CAP_NET_ADMIN | native attach, counters checked against the capture: `RESULT ok` |
| flowsample | CAP_BPF + CAP_NET_ADMIN | refused at load (`!root` — variable offset) |
| flowsample | + CAP_PERFMON | attach, counters, events, the flow table, LastSeen and the capture check: `RESULT ok` |

The XDP veth attach on 6.12.111 / 6.6.157 was not measured (the VM covers load and test run only — the same as bpf-mlir). **The tcx attach was measured on lo in the VM as root and with
{CAP_BPF, CAP_NET_ADMIN} on all three kernels.** The file capability (`setcap`) form was not measured here (the tutorial runs it).

## Hints in error messages

gobpf's `Load` / `LoadUnchecked` add a **line with a likely cause** to the two known failures above (`*gobpf.HintError` — the verdict and type stay the same; `errors.As` reaches
`*PrecheckError` / `*ebpf.VerifierError`, and `errors.Is` reaches EPERM). The text is the same on all three kernels (for flowsample):

```
load: target precheck failed before loading the embedded program: detect support for XDP: load program: operation not permitted
  hint: the target check's capability probe was refused (permission) before the embedded program was loaded — a non-root loader needs CAP_BPF and CAP_NET_ADMIN (docs/nonroot.md)

load: program Sample: load program: permission denied: 112: (0f) r2 += r1: R2 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root (124 line(s) omitted)
  hint: the verifier refused pointer arithmetic for a non-root loader — a variable packet offset (ctx.Check with a non-constant offset), or on 6.x kernels a record array index whose constant default can reach the indexed access (a map value read into a variable before `if i < uint32(len(p.Arr))`), needs CAP_PERFMON in addition to CAP_BPF and CAP_NET_ADMIN (docs/nonroot.md)
```

The probe's hint is chosen by the object's program kinds: the text above is for objects whose kinds need CAP_NET_ADMIN (or only CAP_BPF); an object with a tracepoint or ksyscall program
gets a root-only text, one with a uprobe, uretprobe or usdt program a CAP_SYS_ADMIN text, and one with another tracing kind (fentry, kprobe, lsm, struct_ops and so on) a CAP_PERFMON text —
each naming the kinds (the kernel's rule: is_net_admin_prog_type / is_perfmon_prog_type in kernel/bpf/syscall.c, and the rows above).

A memlock failure (`RemoveMemlock` — no capabilities) comes from the cilium call in the user's code, outside gobpf (there is no hint). The target check's Unknown results (the
`[]requirements.Unmet` that `Load` returns) were **0** for every item that a non-root loader got as far as loading (all three kernels — no `undetermined` line in the logs).
