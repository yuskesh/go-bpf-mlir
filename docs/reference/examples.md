<!-- Generated — do not edit by hand. -->

# Examples

Target: bpf-mlir `v1.20.0` (commit d3e13842). The tables follow what the ebpf-compile of this version accepts and rejects.

Each example package (`examples/` — each has a `-selftest`) with its program kinds, map kinds and the eBPF-side operations it uses. Built from the frontend's analysis only (independent of ebpf-compile and the kernel).

| Package | Kind | Map | Description |
|---|---|---|---|
| `examples/ethercount` | xdp | array | ethercount is an example with an xdp program (the eBPF side) that counts frames per EtherType and IPv4 protocol, and the user-space side that loads and attaches it and prints the counts, in one Go program. |
| `examples/flowsample` | xdp | array, hash, lru_hash, percpu_array, ringbuf | flowsample is an example with an xdp program (the eBPF side) that counts IPv4 frames per protocol (AtomicAdd on an integer map), writes the last frame seen per protocol to a record map (the last writer wins — Update) and sends an event per frame to a ring buffer, and the user-space side that loads and attaches it and reads the events, in one Go program. |
| `examples/forkwatch` | tp_btf | array, hash | forkwatch is a tp_btf example on sched_process_fork: it counts new child processes and threads per parent process (tgid) and records the last child process's comm (a copy of the kernel char[16]), start_time (64 bit) and real_parent tgid (following a pointer with a nil check). |
| `examples/greetwatch` | uprobe | array, ringbuf, stack_trace | greetwatch is a **uprobe** example on the entry of greet(const char *name, uint32_t n) in another binary (target/greeter — a C program): it outputs the call number and the name string to a ring buffer (bpf.UprobeArg and RingBuf.OutputStr). |
| `examples/ipdeny` | xdp | array, lpm_trie | ipdeny is an example that looks up the source IPv4 address by **lpm_trie longest match** (bpf.LPMTrie4) and drops it with XDP if it is a deny prefix (a conditional verdict). |
| `examples/openwatch` | kprobe | hash | openwatch is a **kprobe** example (//gobpf:kprobe) on the entry of the kernel function do_sys_openat2: it counts opens per tgid and splits them by the first argument dirfd (bpf.KprobeArg[int32] — AT_FDCWD = -100 or the fd of an open directory). |
| `examples/pollstack` | fentry | array, perf_event_array, stack_trace | pollstack is an fentry example on the entry of the kernel function do_sys_poll (poll(2) / ppoll(2)): it takes the id of the caller's kernel stack (bpf.StackTrace) and outputs events through a perf event array (bpf.PerfEventArray). |
| `examples/portcount` | xdp | array | portcount is an example with an xdp program that takes the UDP destination port to count as a **.rodata setting** (bpf.Config — the -port value is Set before load) and counts the datagrams to that port in a **.bss counter** (bpf.Global — an atomic Add), and the user-space side that loads, attaches and prints. |
| `examples/syscount` | fentry, fexit | array, hash, ringbuf | syscount is an example with an fentry program that counts calls to the kernel function do_sys_poll (poll(2) / ppoll(2)) per process (tgid), and a ring buffer that outputs the calls of a chosen process as events (pid, time, task name), written in one Go program with the user-space side. |
| `examples/tailparse` | xdp | array, prog_array | tailparse is an example that splits frame parsing into two stages of xdp programs with tail calls. |
| `examples/tccount` | sched_cls (egress), sched_cls (ingress), xdp | array | tccount is an example with three programs (the eBPF side) that count received (XDP and tcx ingress) and sent (tcx egress) frames on one interface per EtherType and IPv4 protocol, and the user-space side that loads and attaches them and prints the counts, in one Go program. |
| `examples/tcpopts` | xdp | array | tcpopts is an example with an xdp program (the eBPF side) that walks the options of IPv4 TCP SYNs with a Go bounded loop and ctx.Check inside the loop and counts the MSS distribution, whether a timestamp is present and why the walk stopped, and the user-space side that loads, attaches and prints, in one Go program. |
| `examples/xdpcount` | xdp | array | xdpcount is the first example: one Go program holds an xdp program (the eBPF side) and the user-space side that loads and attaches it and reads the map, and `go generate && go build` turns it into one binary. |
| `examples/xdpdecap` | xdp | array | xdpdecap is an example with an xdp program (the eBPF side) that strips the tag from tagged frames (outer ethertype 0x88b5 + a 4-byte tag — the same shape as bpf-mlir's docs/examples/xdp_decap.md) in XDP, and the user-space side that loads, attaches and prints, in one Go program. |
| `examples/xdpfwd` | xdp | array, devmap | xdpfwd is an example where an XDP program attached to the -in interface **redirects IPv4 (IHL 5) frames whose UDP destination port is -port to the devmap entry's interface (-out)** (bpf.DevMap.RedirectIf) and passes the rest. |
| `examples/xdpwindow` | xdp | array | xdpwindow is an example that counts, in xdp, the packets in "a fixed time window from the first packet". |

## From operations to examples

| Operation | Package |
|---|---|
| `bpf.Array.AtomicAdd` | `examples/ethercount`, `examples/flowsample`, `examples/greetwatch`, `examples/ipdeny`, `examples/pollstack`, `examples/portcount`, `examples/syscount`, `examples/tailparse`, `examples/tccount`, `examples/tcpopts`, `examples/xdpcount`, `examples/xdpdecap`, `examples/xdpfwd`, `examples/xdpwindow` |
| `bpf.Array.Lookup` | `examples/forkwatch`, `examples/syscount`, `examples/xdpcount`, `examples/xdpwindow` |
| `bpf.Array.Update` | `examples/flowsample`, `examples/forkwatch`, `examples/xdpcount` |
| `bpf.ArrayOfMaps.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.AtomicAdd` | — (no example package; covered by the frontend tests) |
| `bpf.BloomFilter.Peek` | — (no example package; covered by the frontend tests) |
| `bpf.BloomFilter.Push` | — (no example package; covered by the frontend tests) |
| `bpf.CPUMap.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.CPUMap.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupAllow` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupArray.SkbUnder` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupArray.TaskUnder` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupDeny` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupDeviceContext.AccessType` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupDeviceContext.Major` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupDeviceContext.Minor` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupGetsockoptContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupGetsockoptContext.Level` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupGetsockoptContext.Optlen` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupGetsockoptContext.Optname` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSKBEgressContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSKBEgressContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSKBIngressContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSKBIngressContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSetsockoptContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSetsockoptContext.Level` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSetsockoptContext.Optlen` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSetsockoptContext.Optname` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSetsockoptContext.SetOptlen` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.Family` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.Protocol` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.SetMark` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.SrcIP4` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.SrcPort` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSockContext.Type` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSysctlContext.SetNewValue` | — (no example package; covered by the frontend tests) |
| `bpf.CgroupSysctlContext.Write` | — (no example package; covered by the frontend tests) |
| `bpf.CgrpStorage.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.CgrpStorage.Get` | — (no example package; covered by the frontend tests) |
| `bpf.Config.Value` | `examples/forkwatch`, `examples/openwatch`, `examples/pollstack`, `examples/portcount`, `examples/xdpfwd`, `examples/xdpwindow` |
| `bpf.CountDropsIn` | `examples/flowsample` |
| `bpf.CurrentComm` | `examples/syscount` |
| `bpf.CurrentPidTgid` | `examples/greetwatch`, `examples/openwatch`, `examples/pollstack`, `examples/syscount` |
| `bpf.DevMap.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.DevMap.RedirectIf` | `examples/xdpfwd` |
| `bpf.DevMapHash.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.DevMapHash.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.ExtArg` | — (no example package; covered by the frontend tests) |
| `bpf.FentryArg` | — (no example package; covered by the frontend tests) |
| `bpf.FentryArgInt` | — (no example package; covered by the frontend tests) |
| `bpf.FexitContext.Ret` | `examples/syscount` |
| `bpf.FlowContinue` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.Flags` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.NProto` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.Nhoff` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetAddrProto` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetDport` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetIPProto` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetIPv4Dst` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetIPv4Src` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetSport` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDissectorContext.SetThoff` | — (no example package; covered by the frontend tests) |
| `bpf.FlowDrop` | — (no example package; covered by the frontend tests) |
| `bpf.FlowOK` | — (no example package; covered by the frontend tests) |
| `bpf.FmodRetArgInt` | — (no example package; covered by the frontend tests) |
| `bpf.FsessionContext.Cookie` | — (no example package; covered by the frontend tests) |
| `bpf.FsessionContext.IsReturn` | — (no example package; covered by the frontend tests) |
| `bpf.FsessionContext.SetCookie` | — (no example package; covered by the frontend tests) |
| `bpf.Global.Add` | `examples/portcount` |
| `bpf.Global.Load` | — (no example package; covered by the frontend tests) |
| `bpf.Hash.AddOrInit` | `examples/flowsample`, `examples/forkwatch`, `examples/openwatch`, `examples/syscount` |
| `bpf.Hash.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.Hash.Insert` | — (no example package; covered by the frontend tests) |
| `bpf.Hash.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.Hash.Replace` | — (no example package; covered by the frontend tests) |
| `bpf.Hash.Update` | — (no example package; covered by the frontend tests) |
| `bpf.HashOfMaps.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.InnerMap.AtomicAdd` | — (no example package; covered by the frontend tests) |
| `bpf.InnerMap.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.InnerMap.Update` | — (no example package; covered by the frontend tests) |
| `bpf.InodeStorage.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.InodeStorage.Get` | — (no example package; covered by the frontend tests) |
| `bpf.IterContext.Seq` | — (no example package; covered by the frontend tests) |
| `bpf.IterContext.SeqNum` | — (no example package; covered by the frontend tests) |
| `bpf.KernelAddr` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeArg` | `examples/openwatch` |
| `bpf.KprobeRead` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeSessionContext.Cookie` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeSessionContext.IsReturn` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeSessionContext.SetCookie` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeSessionRun` | — (no example package; covered by the frontend tests) |
| `bpf.KprobeSessionSkipReturn` | — (no example package; covered by the frontend tests) |
| `bpf.KretprobeContext.Ret` | — (no example package; covered by the frontend tests) |
| `bpf.KsyscallArg` | — (no example package; covered by the frontend tests) |
| `bpf.KsyscallStr` | — (no example package; covered by the frontend tests) |
| `bpf.KsyscallStrArray` | — (no example package; covered by the frontend tests) |
| `bpf.KtimeNs` | `examples/pollstack`, `examples/syscount`, `examples/xdpwindow` |
| `bpf.LPMTrie4.Lookup` | `examples/ipdeny` |
| `bpf.LRUHash.AddOrInit` | — (no example package; covered by the frontend tests) |
| `bpf.LRUHash.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.LRUHash.Insert` | — (no example package; covered by the frontend tests) |
| `bpf.LRUHash.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.LRUHash.Replace` | — (no example package; covered by the frontend tests) |
| `bpf.LRUHash.Update` | `examples/flowsample` |
| `bpf.LRUPerCPUHash.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.LRUPerCPUHash.Insert` | — (no example package; covered by the frontend tests) |
| `bpf.LRUPerCPUHash.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.LRUPerCPUHash.Replace` | — (no example package; covered by the frontend tests) |
| `bpf.LRUPerCPUHash.Update` | — (no example package; covered by the frontend tests) |
| `bpf.LSMAllow` | — (no example package; covered by the frontend tests) |
| `bpf.LSMArg` | — (no example package; covered by the frontend tests) |
| `bpf.LSMArgInt` | — (no example package; covered by the frontend tests) |
| `bpf.LSMDeny` | — (no example package; covered by the frontend tests) |
| `bpf.LWTDrop` | — (no example package; covered by the frontend tests) |
| `bpf.LWTInContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.LWTInContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.LWTOK` | — (no example package; covered by the frontend tests) |
| `bpf.LWTOutContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.LWTOutContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.LWTXmitContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.LWTXmitContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.NFAccept` | — (no example package; covered by the frontend tests) |
| `bpf.NFDrop` | — (no example package; covered by the frontend tests) |
| `bpf.NetfilterContext.Hook` | — (no example package; covered by the frontend tests) |
| `bpf.NetfilterContext.PF` | — (no example package; covered by the frontend tests) |
| `bpf.NetfilterContext.SkbLen` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUArray.AtomicAdd` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUArray.Lookup` | `examples/flowsample` |
| `bpf.PerCPUArray.Update` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUHash.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUHash.Insert` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUHash.Lookup` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUHash.Replace` | — (no example package; covered by the frontend tests) |
| `bpf.PerCPUHash.Update` | — (no example package; covered by the frontend tests) |
| `bpf.PerfEventArray.Output` | `examples/pollstack` |
| `bpf.PerfEventContext.SamplePeriod` | — (no example package; covered by the frontend tests) |
| `bpf.ProbeTargetIndex` | — (no example package; covered by the frontend tests) |
| `bpf.ProgArray.TailCall` | — (no example package; covered by the frontend tests) |
| `bpf.ProgArray.TailCallIf` | `examples/tailparse` |
| `bpf.Queue.Peek` | — (no example package; covered by the frontend tests) |
| `bpf.Queue.Pop` | — (no example package; covered by the frontend tests) |
| `bpf.Queue.Push` | — (no example package; covered by the frontend tests) |
| `bpf.RawTPArg` | — (no example package; covered by the frontend tests) |
| `bpf.RawTPWritableContext.Buffer` | — (no example package; covered by the frontend tests) |
| `bpf.RawTPWritableContext.SetBuffer` | — (no example package; covered by the frontend tests) |
| `bpf.ReuseportSockArray.Select` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.Discard` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.Output` | `examples/flowsample`, `examples/syscount` |
| `bpf.RingBuf.OutputBuf` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.OutputKernelStr` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.OutputStr` | `examples/greetwatch` |
| `bpf.RingBuf.OutputStrOrDiscard` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.Reserve` | — (no example package; covered by the frontend tests) |
| `bpf.RingBuf.Submit` | — (no example package; covered by the frontend tests) |
| `bpf.SKDrop` | — (no example package; covered by the frontend tests) |
| `bpf.SKMsgContext.LocalIP4` | — (no example package; covered by the frontend tests) |
| `bpf.SKMsgContext.LocalPort` | — (no example package; covered by the frontend tests) |
| `bpf.SKMsgContext.RemoteIP4` | — (no example package; covered by the frontend tests) |
| `bpf.SKMsgContext.RemotePort` | — (no example package; covered by the frontend tests) |
| `bpf.SKMsgContext.Size` | — (no example package; covered by the frontend tests) |
| `bpf.SKPass` | — (no example package; covered by the frontend tests) |
| `bpf.SKSKBContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.SKSKBContext.LocalPort` | — (no example package; covered by the frontend tests) |
| `bpf.SKStorage.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.SKStorage.Get` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6Drop` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.Ifindex` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.Mark` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.Priority` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.Protocol` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.SetMark` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6LocalContext.SetPriority` | — (no example package; covered by the frontend tests) |
| `bpf.Seg6OK` | — (no example package; covered by the frontend tests) |
| `bpf.SeqFile.Write` | — (no example package; covered by the frontend tests) |
| `bpf.SkLookupContext.Family` | — (no example package; covered by the frontend tests) |
| `bpf.SkLookupContext.LocalIP4` | — (no example package; covered by the frontend tests) |
| `bpf.SkLookupContext.LocalPort` | — (no example package; covered by the frontend tests) |
| `bpf.SkLookupContext.Protocol` | — (no example package; covered by the frontend tests) |
| `bpf.SkLookupContext.RemotePort` | — (no example package; covered by the frontend tests) |
| `bpf.SkReuseportContext.BindInany` | — (no example package; covered by the frontend tests) |
| `bpf.SkReuseportContext.EthProtocol` | — (no example package; covered by the frontend tests) |
| `bpf.SkReuseportContext.Hash` | — (no example package; covered by the frontend tests) |
| `bpf.SkReuseportContext.IPProtocol` | — (no example package; covered by the frontend tests) |
| `bpf.SkReuseportContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.Family` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.Protocol` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.SetUserIP4` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.SetUserPort` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.Type` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.UserIP4` | — (no example package; covered by the frontend tests) |
| `bpf.SockAddrContext.UserPort` | — (no example package; covered by the frontend tests) |
| `bpf.SockHash.Assign` | — (no example package; covered by the frontend tests) |
| `bpf.SockHash.Insert` | — (no example package; covered by the frontend tests) |
| `bpf.SockHash.MsgRedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.SockHash.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.SockMap.Assign` | — (no example package; covered by the frontend tests) |
| `bpf.SockMap.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.SockOpsContext.Family` | — (no example package; covered by the frontend tests) |
| `bpf.SockOpsContext.LocalPort` | — (no example package; covered by the frontend tests) |
| `bpf.SockOpsContext.Op` | — (no example package; covered by the frontend tests) |
| `bpf.SockOpsContext.RemotePort` | — (no example package; covered by the frontend tests) |
| `bpf.SockOpsContext.SetReply` | — (no example package; covered by the frontend tests) |
| `bpf.SocketDrop` | — (no example package; covered by the frontend tests) |
| `bpf.SocketFilterContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.SocketKeep` | — (no example package; covered by the frontend tests) |
| `bpf.Stack.Peek` | — (no example package; covered by the frontend tests) |
| `bpf.Stack.Pop` | — (no example package; covered by the frontend tests) |
| `bpf.Stack.Push` | — (no example package; covered by the frontend tests) |
| `bpf.StackBuildID.UserID` | — (no example package; covered by the frontend tests) |
| `bpf.StackBuildID.UserIDReuse` | `examples/greetwatch` |
| `bpf.StackTrace.KernelID` | `examples/pollstack` |
| `bpf.StackTrace.KernelIDReuse` | — (no example package; covered by the frontend tests) |
| `bpf.StackTrace.UserID` | — (no example package; covered by the frontend tests) |
| `bpf.StackTrace.UserIDReuse` | `examples/greetwatch` |
| `bpf.StructOpsArg` | — (no example package; covered by the frontend tests) |
| `bpf.StructOpsArgInt` | — (no example package; covered by the frontend tests) |
| `bpf.SysBpf` | — (no example package; covered by the frontend tests) |
| `bpf.SysClose` | — (no example package; covered by the frontend tests) |
| `bpf.SyscallLoad` | — (no example package; covered by the frontend tests) |
| `bpf.TCActContext.Check` | — (no example package; covered by the frontend tests) |
| `bpf.TCActContext.Len` | — (no example package; covered by the frontend tests) |
| `bpf.TCActContext.SetMark` | — (no example package; covered by the frontend tests) |
| `bpf.TCActOK` | — (no example package; covered by the frontend tests) |
| `bpf.TCActPipe` | — (no example package; covered by the frontend tests) |
| `bpf.TCActShot` | — (no example package; covered by the frontend tests) |
| `bpf.TCDrop` | — (no example package; covered by the frontend tests) |
| `bpf.TCEgressContext.Check` | `examples/tccount` |
| `bpf.TCEgressContext.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.TCEgressContext.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.TCIngressContext.Check` | `examples/tccount` |
| `bpf.TCIngressContext.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.TCIngressContext.RedirectIf` | — (no example package; covered by the frontend tests) |
| `bpf.TCPass` | `examples/tccount` |
| `bpf.TPArg` | `examples/forkwatch` |
| `bpf.TPArgInt` | — (no example package; covered by the frontend tests) |
| `bpf.TaskStorage.Delete` | — (no example package; covered by the frontend tests) |
| `bpf.TaskStorage.Get` | — (no example package; covered by the frontend tests) |
| `bpf.Timer.Init` | `examples/xdpwindow` |
| `bpf.Timer.SetCallback` | `examples/xdpwindow` |
| `bpf.Timer.Start` | `examples/xdpwindow` |
| `bpf.TracepointContext.Event` | — (no example package; covered by the frontend tests) |
| `bpf.USDTArg` | — (no example package; covered by the frontend tests) |
| `bpf.UprobeArg` | `examples/greetwatch` |
| `bpf.UprobeBuf` | — (no example package; covered by the frontend tests) |
| `bpf.UprobeStr` | `examples/greetwatch` |
| `bpf.UretprobeContext.Ret` | — (no example package; covered by the frontend tests) |
| `bpf.UserRingBuf.Drain` | — (no example package; covered by the frontend tests) |
| `bpf.UserStrArray.At` | — (no example package; covered by the frontend tests) |
| `bpf.Window.BE16` | `examples/ethercount`, `examples/flowsample`, `examples/ipdeny`, `examples/portcount`, `examples/tailparse`, `examples/tccount`, `examples/tcpopts`, `examples/xdpdecap`, `examples/xdpfwd` |
| `bpf.Window.BE32` | `examples/xdpdecap` |
| `bpf.Window.BE64` | `examples/xdpdecap` |
| `bpf.Window.LE16` | — (no example package; covered by the frontend tests) |
| `bpf.Window.LE32` | — (no example package; covered by the frontend tests) |
| `bpf.Window.LE64` | — (no example package; covered by the frontend tests) |
| `bpf.Window.SetBE16` | `examples/xdpdecap` |
| `bpf.Window.SetBE32` | `examples/xdpdecap` |
| `bpf.Window.SetBE64` | `examples/xdpdecap` |
| `bpf.Window.SetLE16` | — (no example package; covered by the frontend tests) |
| `bpf.Window.SetLE32` | — (no example package; covered by the frontend tests) |
| `bpf.Window.SetLE64` | — (no example package; covered by the frontend tests) |
| `bpf.Window.SetU8` | — (no example package; covered by the frontend tests) |
| `bpf.Window.U8` | `examples/ethercount`, `examples/flowsample`, `examples/ipdeny`, `examples/portcount`, `examples/tailparse`, `examples/tccount`, `examples/tcpopts`, `examples/xdpfwd`, `examples/xdpwindow` |
| `bpf.WithLock` | `examples/xdpwindow` |
| `bpf.XDPAborted` | — (no example package; covered by the frontend tests) |
| `bpf.XDPContext.AdjustHead` | `examples/xdpdecap` |
| `bpf.XDPContext.AdjustTail` | — (no example package; covered by the frontend tests) |
| `bpf.XDPContext.Check` | `examples/ethercount`, `examples/flowsample`, `examples/ipdeny`, `examples/portcount`, `examples/tailparse`, `examples/tccount`, `examples/tcpopts`, `examples/xdpdecap`, `examples/xdpfwd`, `examples/xdpwindow` |
| `bpf.XDPDrop` | `examples/ipdeny` |
| `bpf.XDPPass` | `examples/ethercount`, `examples/flowsample`, `examples/ipdeny`, `examples/portcount`, `examples/tailparse`, `examples/tccount`, `examples/tcpopts`, `examples/xdpcount`, `examples/xdpdecap`, `examples/xdpfwd`, `examples/xdpwindow` |
| `bpf.XDPTx` | — (no example package; covered by the frontend tests) |
| `bpf.XSKMap.Redirect` | — (no example package; covered by the frontend tests) |
| `bpf.XSKMap.RedirectIf` | — (no example package; covered by the frontend tests) |

Operations no generated package uses (generated and compiled in the frontend tests only): `bpf.CgroupGetsockoptContext.SetOptlen`, `bpf.CgroupSysctlContext.FilePos`, `bpf.CgroupSysctlContext.SetFilePos`, `bpf.FlowDissectorContext.AddrProto`, `bpf.FlowDissectorContext.Dport`, `bpf.FlowDissectorContext.FlowLabel`, `bpf.FlowDissectorContext.IPProto`, `bpf.FlowDissectorContext.IPv4Dst`, `bpf.FlowDissectorContext.IPv4Src`, `bpf.FlowDissectorContext.IsEncap`, `bpf.FlowDissectorContext.IsFirstFrag`, `bpf.FlowDissectorContext.IsFrag`, `bpf.FlowDissectorContext.SetFlags`, `bpf.FlowDissectorContext.SetFlowLabel`, `bpf.FlowDissectorContext.SetIsEncap`, `bpf.FlowDissectorContext.SetIsFirstFrag`, `bpf.FlowDissectorContext.SetIsFrag`, `bpf.FlowDissectorContext.SetNProto`, `bpf.FlowDissectorContext.SetNhoff`, `bpf.FlowDissectorContext.Sport`, `bpf.FlowDissectorContext.Thoff`, `bpf.SKMsgContext.Family`, `bpf.SockHash.MsgRedirect`, `bpf.SockHash.Redirect`, `bpf.SockMap.Insert`, `bpf.SockMap.MsgRedirect`, `bpf.SockMap.MsgRedirectIf`, `bpf.SockMap.Redirect`
