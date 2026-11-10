<!-- Generated — do not edit by hand. -->

# bpf-mlir ops the frontend emits

Target: bpf-mlir `v1.21.0` (commit 41b18856). The tables follow what the ebpf-compile of this version accepts and rejects.

The set of ops the frontend may emit into the generated `.mlir` (allowedOps in `internal/frontend/bpfworld.go` — emitting any other op is a frontend bug, GB015) and the Go forms that emit each op. The meaning of each op is in bpf-mlir's op reference (`docs/reference/ebpf_ops.md` in the bpf-mlir source release).

| Op | Go forms that emit it |
|---|---|
| `arith.addi` | `+` |
| `arith.andi` | `&` (and the side-effect-free form of bool `&&`) |
| `arith.cmpi` | comparison operators |
| `arith.constant` | a Go constant |
| `arith.divsi` | signed `/` (the divisor is a constant ±2^k) |
| `arith.divui` | unsigned `/` (a non-zero constant divisor) and the expansion of a general signed constant divisor |
| `arith.extsi` | signed type conversion (widening) |
| `arith.extui` | unsigned type conversion (widening), widening bool to i8 |
| `arith.muli` | `*` |
| `arith.ori` | `\|` (and `\|\|`) |
| `arith.remsi` | signed `%` (the divisor is a constant ±2^k) |
| `arith.remui` | unsigned `%` and the signed expansion |
| `arith.select` | the sign correction for a general signed constant divisor |
| `arith.shli` | `<<` (a constant shift) |
| `arith.shrsi` | signed `>>` |
| `arith.shrui` | unsigned `>>` |
| `arith.subi` | `-` |
| `arith.trunci` | type conversion (narrowing) |
| `arith.xori` | `^` |
| `ebpf.bloom.peek` | `bpf.BloomFilter.Peek` |
| `ebpf.break` | `break` inside a `for` (the last statement of an if / Check branch) |
| `ebpf.byteorder.from_be` | `bpf.Window.BE16`, `bpf.Window.BE32`, `bpf.Window.BE64`, `bpf.Window.LE16`, `bpf.Window.LE32`, `bpf.Window.LE64`, `bpf.Window.U8` |
| `ebpf.byteorder.to_be` | `bpf.Window.SetBE16`, `bpf.Window.SetBE32`, `bpf.Window.SetBE64`, `bpf.Window.SetLE16`, `bpf.Window.SetLE32`, `bpf.Window.SetLE64`, `bpf.Window.SetU8` |
| `ebpf.call` | a subprogram call |
| `ebpf.continue` | `continue` inside a `for` (the last statement of an if / Check branch) |
| `ebpf.ctx.arg` | `bpf.FentryArgInt`, `bpf.FentryArg`, `bpf.IterContext.SeqNum`, `bpf.IterContext.Seq`, `bpf.StructOpsArgInt`, `bpf.StructOpsArg`, `bpf.TPArgInt`, `bpf.TPArg` |
| `ebpf.ctx.field` | `bpf.CgroupDeviceContext.AccessType`, `bpf.CgroupDeviceContext.Major`, `bpf.CgroupDeviceContext.Minor`, `bpf.CgroupGetsockoptContext.Level`, `bpf.CgroupGetsockoptContext.Optlen`, `bpf.CgroupGetsockoptContext.Optname`, `bpf.CgroupGetsockoptContext.SetOptlen`, `bpf.CgroupSKBEgressContext.Len`, `bpf.CgroupSKBIngressContext.Len`, `bpf.CgroupSetsockoptContext.Level`, `bpf.CgroupSetsockoptContext.Optlen`, `bpf.CgroupSetsockoptContext.Optname`, `bpf.CgroupSetsockoptContext.SetOptlen`, `bpf.CgroupSockContext.Family`, `bpf.CgroupSockContext.Protocol`, `bpf.CgroupSockContext.SetMark`, `bpf.CgroupSockContext.SrcIP4`, `bpf.CgroupSockContext.SrcPort`, `bpf.CgroupSockContext.Type`, `bpf.CgroupSysctlContext.FilePos`, `bpf.CgroupSysctlContext.SetFilePos`, `bpf.CgroupSysctlContext.Write`, `bpf.LWTInContext.Len`, `bpf.LWTOutContext.Len`, `bpf.LWTXmitContext.Len`, `bpf.NetfilterContext.Hook`, `bpf.NetfilterContext.PF`, `bpf.NetfilterContext.SkbLen`, `bpf.RawTPArg`, `bpf.SKMsgContext.Family`, `bpf.SKMsgContext.LocalIP4`, `bpf.SKMsgContext.LocalPort`, `bpf.SKMsgContext.RemoteIP4`, `bpf.SKMsgContext.RemotePort`, `bpf.SKMsgContext.Size`, `bpf.SKSKBContext.Len`, `bpf.SKSKBContext.LocalPort`, `bpf.Seg6LocalContext.Ifindex`, `bpf.Seg6LocalContext.Len`, `bpf.Seg6LocalContext.Mark`, `bpf.Seg6LocalContext.Priority`, `bpf.Seg6LocalContext.Protocol`, `bpf.Seg6LocalContext.SetMark`, `bpf.Seg6LocalContext.SetPriority`, `bpf.SkLookupContext.Family`, `bpf.SkLookupContext.LocalIP4`, `bpf.SkLookupContext.LocalPort`, `bpf.SkLookupContext.Protocol`, `bpf.SkLookupContext.RemotePort`, `bpf.SkReuseportContext.BindInany`, `bpf.SkReuseportContext.EthProtocol`, `bpf.SkReuseportContext.Hash`, `bpf.SkReuseportContext.IPProtocol`, `bpf.SkReuseportContext.Len`, `bpf.SockAddrContext.Family`, `bpf.SockAddrContext.Protocol`, `bpf.SockAddrContext.SetUserIP4`, `bpf.SockAddrContext.SetUserPort`, `bpf.SockAddrContext.Type`, `bpf.SockAddrContext.UserIP4`, `bpf.SockAddrContext.UserPort`, `bpf.SockOpsContext.Family`, `bpf.SockOpsContext.LocalPort`, `bpf.SockOpsContext.Op`, `bpf.SockOpsContext.RemotePort`, `bpf.SockOpsContext.SetReply`, `bpf.SocketFilterContext.Len`, `bpf.TCActContext.Len`, `bpf.TCActContext.SetMark` |
| `ebpf.ctx.field.store` | `bpf.CgroupDeviceContext.AccessType`, `bpf.CgroupDeviceContext.Major`, `bpf.CgroupDeviceContext.Minor`, `bpf.CgroupGetsockoptContext.Level`, `bpf.CgroupGetsockoptContext.Optlen`, `bpf.CgroupGetsockoptContext.Optname`, `bpf.CgroupGetsockoptContext.SetOptlen`, `bpf.CgroupSKBEgressContext.Len`, `bpf.CgroupSKBIngressContext.Len`, `bpf.CgroupSetsockoptContext.Level`, `bpf.CgroupSetsockoptContext.Optlen`, `bpf.CgroupSetsockoptContext.Optname`, `bpf.CgroupSetsockoptContext.SetOptlen`, `bpf.CgroupSockContext.Family`, `bpf.CgroupSockContext.Protocol`, `bpf.CgroupSockContext.SetMark`, `bpf.CgroupSockContext.SrcIP4`, `bpf.CgroupSockContext.SrcPort`, `bpf.CgroupSockContext.Type`, `bpf.CgroupSysctlContext.FilePos`, `bpf.CgroupSysctlContext.SetFilePos`, `bpf.CgroupSysctlContext.Write`, `bpf.LWTInContext.Len`, `bpf.LWTOutContext.Len`, `bpf.LWTXmitContext.Len`, `bpf.SKMsgContext.Family`, `bpf.SKMsgContext.LocalIP4`, `bpf.SKMsgContext.LocalPort`, `bpf.SKMsgContext.RemoteIP4`, `bpf.SKMsgContext.RemotePort`, `bpf.SKMsgContext.Size`, `bpf.SKSKBContext.Len`, `bpf.SKSKBContext.LocalPort`, `bpf.Seg6LocalContext.Ifindex`, `bpf.Seg6LocalContext.Len`, `bpf.Seg6LocalContext.Mark`, `bpf.Seg6LocalContext.Priority`, `bpf.Seg6LocalContext.Protocol`, `bpf.Seg6LocalContext.SetMark`, `bpf.Seg6LocalContext.SetPriority`, `bpf.SkLookupContext.Family`, `bpf.SkLookupContext.LocalIP4`, `bpf.SkLookupContext.LocalPort`, `bpf.SkLookupContext.Protocol`, `bpf.SkLookupContext.RemotePort`, `bpf.SkReuseportContext.BindInany`, `bpf.SkReuseportContext.EthProtocol`, `bpf.SkReuseportContext.Hash`, `bpf.SkReuseportContext.IPProtocol`, `bpf.SkReuseportContext.Len`, `bpf.SockAddrContext.Family`, `bpf.SockAddrContext.Protocol`, `bpf.SockAddrContext.SetUserIP4`, `bpf.SockAddrContext.SetUserPort`, `bpf.SockAddrContext.Type`, `bpf.SockAddrContext.UserIP4`, `bpf.SockAddrContext.UserPort`, `bpf.SockOpsContext.Family`, `bpf.SockOpsContext.LocalPort`, `bpf.SockOpsContext.Op`, `bpf.SockOpsContext.RemotePort`, `bpf.SockOpsContext.SetReply`, `bpf.SocketFilterContext.Len`, `bpf.TCActContext.Len`, `bpf.TCActContext.SetMark` |
| `ebpf.ctx.load` | `bpf.SyscallLoad` |
| `ebpf.ctx.retval` | `bpf.FexitContext.Ret` |
| `ebpf.dynptr.read` | `bpf.UserRingBuf.Drain` |
| `ebpf.elem.load` | a read of a record array element |
| `ebpf.elem.store` | an assignment to a record array element |
| `ebpf.ext.arg` | `bpf.ExtArg` |
| `ebpf.flow_keys.load` | `bpf.FlowDissectorContext.AddrProto`, `bpf.FlowDissectorContext.Dport`, `bpf.FlowDissectorContext.Flags`, `bpf.FlowDissectorContext.FlowLabel`, `bpf.FlowDissectorContext.IPProto`, `bpf.FlowDissectorContext.IPv4Dst`, `bpf.FlowDissectorContext.IPv4Src`, `bpf.FlowDissectorContext.IsEncap`, `bpf.FlowDissectorContext.IsFirstFrag`, `bpf.FlowDissectorContext.IsFrag`, `bpf.FlowDissectorContext.NProto`, `bpf.FlowDissectorContext.Nhoff`, `bpf.FlowDissectorContext.Sport`, `bpf.FlowDissectorContext.Thoff` |
| `ebpf.flow_keys.store` | `bpf.FlowDissectorContext.SetAddrProto`, `bpf.FlowDissectorContext.SetDport`, `bpf.FlowDissectorContext.SetFlags`, `bpf.FlowDissectorContext.SetFlowLabel`, `bpf.FlowDissectorContext.SetIPProto`, `bpf.FlowDissectorContext.SetIPv4Dst`, `bpf.FlowDissectorContext.SetIPv4Src`, `bpf.FlowDissectorContext.SetIsEncap`, `bpf.FlowDissectorContext.SetIsFirstFrag`, `bpf.FlowDissectorContext.SetIsFrag`, `bpf.FlowDissectorContext.SetNProto`, `bpf.FlowDissectorContext.SetNhoff`, `bpf.FlowDissectorContext.SetSport`, `bpf.FlowDissectorContext.SetThoff` |
| `ebpf.func` | a subprogram (a function of the same package called from a program) |
| `ebpf.global.atomic_add` | `bpf.Global.Add` |
| `ebpf.global.load` | `bpf.Config.Value`, `bpf.Global.Load` |
| `ebpf.if` | `bpf.RingBuf.OutputStrOrDiscard`, an `if` statement (and the join after a Lookup's present check) |
| `ebpf.if.yield` | the end of an `if` branch |
| `ebpf.kernel.read_scalar` | `bpf.KprobeRead` |
| `ebpf.kernel.read_str` | `bpf.RingBuf.OutputKernelStr` |
| `ebpf.kfield.copy` | copying a kernel [N]byte field `q.F = p.G` (q is a checked record pointer) |
| `ebpf.kfield.load` | `bpf.IterContext.SeqNum`, `bpf.NetfilterContext.Hook`, `bpf.NetfilterContext.PF`, `bpf.NetfilterContext.SkbLen`, a kernel struct field read `p.F` (p is a kernel pointer from checking bpf.TPArg[T] or bpf.FentryArg[T], or from following a pointer field) |
| `ebpf.kfield.ptr` | `bpf.IterContext.Seq`, following a kernel pointer field `if m := p.F; m != nil { … }` (F is *U) |
| `ebpf.kfield.store` | a struct_ops write of a kernel integer field `sk.F = v` (sk is a checked StructOpsArg pointer) |
| `ebpf.kprobe.arg` | `bpf.KprobeArg`, `bpf.KprobeRead` |
| `ebpf.kptr.addr` | the address of a checked kernel pointer as an integer `bpf.KernelAddr(p)` |
| `ebpf.kptr.check` | `bpf.FentryArg`, `bpf.IterContext.Seq`, `bpf.StructOpsArg`, `bpf.TPArg`, the check of a kernel pointer that can be NULL `if m := …; m != nil { … } [else { … }]` |
| `ebpf.ksyscall.arg` | `bpf.KsyscallArg`, `bpf.KsyscallStrArray`, `bpf.KsyscallStr` |
| `ebpf.ktime.ns` | `bpf.KtimeNs` |
| `ebpf.loop` | a bounded `for` (`for i := range N` / `for i := T(0); i < N; i++` — always unrolled) |
| `ebpf.loop.yield` | the end of a bounded `for` body |
| `ebpf.map.atomic_add` | `bpf.Array.AtomicAdd`, `bpf.CountDropsIn`, `bpf.InnerMap.AtomicAdd`, `bpf.PerCPUArray.AtomicAdd` |
| `ebpf.map.inner` | `bpf.ArrayOfMaps.Lookup`, `bpf.HashOfMaps.Lookup` |
| `ebpf.map.lookup` | `bpf.Array.Lookup`, `bpf.ArrayOfMaps.Lookup`, `bpf.Hash.AddOrInit`, `bpf.Hash.Lookup`, `bpf.HashOfMaps.Lookup`, `bpf.InnerMap.Lookup`, `bpf.LPMTrie4.Lookup`, `bpf.LRUHash.AddOrInit`, `bpf.LRUHash.Lookup`, `bpf.LRUPerCPUHash.Lookup`, `bpf.PerCPUArray.Lookup`, `bpf.PerCPUHash.Lookup` |
| `ebpf.map.peek` | `bpf.Queue.Peek`, `bpf.Stack.Peek` |
| `ebpf.map.pop` | `bpf.Queue.Pop`, `bpf.Stack.Pop` |
| `ebpf.map.push` | `bpf.BloomFilter.Push`, `bpf.Queue.Push`, `bpf.Stack.Push` |
| `ebpf.map.try_delete` | `bpf.Hash.Delete`, `bpf.LRUHash.Delete`, `bpf.LRUPerCPUHash.Delete`, `bpf.PerCPUHash.Delete` |
| `ebpf.map.try_update` | `bpf.Hash.AddOrInit`, `bpf.Hash.Insert`, `bpf.Hash.Replace`, `bpf.Hash.Update`, `bpf.LRUHash.AddOrInit`, `bpf.LRUHash.Insert`, `bpf.LRUHash.Replace`, `bpf.LRUHash.Update`, `bpf.LRUPerCPUHash.Insert`, `bpf.LRUPerCPUHash.Replace`, `bpf.LRUPerCPUHash.Update`, `bpf.PerCPUHash.Insert`, `bpf.PerCPUHash.Replace`, `bpf.PerCPUHash.Update` |
| `ebpf.map.update` | `bpf.Array.Update`, `bpf.InnerMap.Update`, `bpf.PerCPUArray.Update` |
| `ebpf.msg.redirect` | `bpf.SockHash.MsgRedirectIf`, `bpf.SockHash.MsgRedirect`, `bpf.SockMap.MsgRedirectIf`, `bpf.SockMap.MsgRedirect` |
| `ebpf.packet.check` | `bpf.CgroupGetsockoptContext.Check`, `bpf.CgroupSKBEgressContext.Check`, `bpf.CgroupSKBIngressContext.Check`, `bpf.CgroupSetsockoptContext.Check`, `bpf.FlowDissectorContext.Check`, `bpf.LWTInContext.Check`, `bpf.LWTOutContext.Check`, `bpf.LWTXmitContext.Check`, `bpf.TCActContext.Check`, `bpf.TCEgressContext.Check`, `bpf.TCIngressContext.Check`, `bpf.XDPContext.Check` |
| `ebpf.packet.store` | `bpf.Window.SetBE16`, `bpf.Window.SetBE32`, `bpf.Window.SetBE64`, `bpf.Window.SetLE16`, `bpf.Window.SetLE32`, `bpf.Window.SetLE64`, `bpf.Window.SetU8` |
| `ebpf.packet.window_load` | `bpf.Window.BE16`, `bpf.Window.BE32`, `bpf.Window.BE64`, `bpf.Window.LE16`, `bpf.Window.LE32`, `bpf.Window.LE64`, `bpf.Window.U8` |
| `ebpf.perf.output` | `bpf.PerfEventArray.Output` |
| `ebpf.probe.retval` | `bpf.KretprobeContext.Ret`, `bpf.UretprobeContext.Ret` |
| `ebpf.probe.target_index` | `bpf.ProbeTargetIndex` |
| `ebpf.program` | a program function (a top-level function whose first parameter is a context type) |
| `ebpf.record.make` | `bpf.LPMTrie4.Lookup`, `bpf.PerfEventArray.Output`, `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr`, `bpf.SeqFile.Write`, `bpf.SysBpf`, a record composite literal (an Update value, an Output event) |
| `ebpf.redirect` | `bpf.TCEgressContext.RedirectIf`, `bpf.TCEgressContext.Redirect`, `bpf.TCIngressContext.RedirectIf`, `bpf.TCIngressContext.Redirect` |
| `ebpf.redirect_map` | `bpf.CPUMap.RedirectIf`, `bpf.CPUMap.Redirect`, `bpf.DevMap.RedirectIf`, `bpf.DevMap.Redirect`, `bpf.DevMapHash.RedirectIf`, `bpf.DevMapHash.Redirect`, `bpf.XSKMap.RedirectIf`, `bpf.XSKMap.Redirect` |
| `ebpf.ref.atomic_add` | `bpf.Hash.AddOrInit`, `bpf.LRUHash.AddOrInit`, the addition to an existing value in Hash.AddOrInit |
| `ebpf.ref.check` | `bpf.Array.Lookup`, `bpf.ArrayOfMaps.Lookup`, `bpf.CgrpStorage.Get`, `bpf.Hash.AddOrInit`, `bpf.Hash.Lookup`, `bpf.HashOfMaps.Lookup`, `bpf.InnerMap.Lookup`, `bpf.InodeStorage.Get`, `bpf.LPMTrie4.Lookup`, `bpf.LRUHash.AddOrInit`, `bpf.LRUHash.Lookup`, `bpf.LRUPerCPUHash.Lookup`, `bpf.PerCPUArray.Lookup`, `bpf.PerCPUHash.Lookup`, `bpf.SKStorage.Get`, `bpf.TaskStorage.Get` |
| `ebpf.ref.field.atomic_add` | `bpf.AtomicAdd` |
| `ebpf.ref.field.load` | a record field read (`p.F`) |
| `ebpf.ref.field.store` | an assignment to a record field (`p.F = v`, `p.F += v`) |
| `ebpf.ref.index` | a variable index into a record array (`if i < uint32(len(p.Arr)) { p.Arr[i] }`) |
| `ebpf.ref.load` | `bpf.Array.Lookup`, `bpf.Hash.Lookup`, `bpf.InnerMap.Lookup`, `bpf.LPMTrie4.Lookup`, `bpf.LRUHash.Lookup`, `bpf.LRUPerCPUHash.Lookup`, `bpf.PerCPUArray.Lookup`, `bpf.PerCPUHash.Lookup`, a `*p` read inside a Lookup's checked branch |
| `ebpf.return` | a subprogram's `return <value>` |
| `ebpf.ringbuf.discard` | `bpf.RingBuf.OutputStrOrDiscard` |
| `ebpf.ringbuf.if_reserved` | `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr`, `bpf.RingBuf.Output` |
| `ebpf.ringbuf.reserve` | `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr`, `bpf.RingBuf.Output` |
| `ebpf.ringbuf.store_field` | `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStr` |
| `ebpf.ringbuf.store_record` | `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr`, `bpf.RingBuf.Output` |
| `ebpf.ringbuf.submit` | `bpf.RingBuf.OutputBuf`, `bpf.RingBuf.OutputKernelStr`, `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr`, `bpf.RingBuf.Output` |
| `ebpf.seq.write` | `bpf.SeqFile.Write` |
| `ebpf.session.cookie.load` | `bpf.FsessionContext.Cookie`, `bpf.KprobeSessionContext.Cookie` |
| `ebpf.session.cookie.store` | `bpf.FsessionContext.SetCookie`, `bpf.KprobeSessionContext.SetCookie` |
| `ebpf.session.is_return` | `bpf.FsessionContext.IsReturn`, `bpf.KprobeSessionContext.IsReturn` |
| `ebpf.sk.assign` | `bpf.SockHash.Assign`, `bpf.SockMap.Assign` |
| `ebpf.sk.redirect` | `bpf.SockHash.RedirectIf`, `bpf.SockHash.Redirect`, `bpf.SockMap.RedirectIf`, `bpf.SockMap.Redirect` |
| `ebpf.sk.select_reuseport` | `bpf.ReuseportSockArray.Select` |
| `ebpf.skb.under_cgroup` | `bpf.CgroupArray.SkbUnder` |
| `ebpf.sock.map_lookup` | `bpf.SockHash.Assign`, `bpf.SockMap.Assign` |
| `ebpf.sock.map_update` | `bpf.SockHash.Insert`, `bpf.SockMap.Insert` |
| `ebpf.sock.ref_check` | `bpf.SockHash.Assign`, `bpf.SockMap.Assign` |
| `ebpf.sock.release` | `bpf.SockHash.Assign`, `bpf.SockMap.Assign` |
| `ebpf.spin.region` | `bpf.WithLock` |
| `ebpf.stack.kernel_id` | `bpf.StackTrace.KernelIDReuse`, `bpf.StackTrace.KernelID` |
| `ebpf.stack.user_id` | `bpf.StackBuildID.UserIDReuse`, `bpf.StackBuildID.UserID`, `bpf.StackTrace.UserIDReuse`, `bpf.StackTrace.UserID` |
| `ebpf.storage.delete` | `bpf.CgrpStorage.Delete`, `bpf.InodeStorage.Delete`, `bpf.SKStorage.Delete`, `bpf.TaskStorage.Delete` |
| `ebpf.storage.get` | `bpf.CgrpStorage.Get`, `bpf.InodeStorage.Get`, `bpf.SKStorage.Get`, `bpf.TaskStorage.Get` |
| `ebpf.sys.bpf` | `bpf.SysBpf` |
| `ebpf.sys.close` | `bpf.SysClose` |
| `ebpf.sysctl.set_new_value` | `bpf.CgroupSysctlContext.SetNewValue` |
| `ebpf.tail_call` | `bpf.ProgArray.TailCallIf`, `bpf.ProgArray.TailCall` |
| `ebpf.task.comm` | `bpf.CurrentComm` |
| `ebpf.task.pid_tgid` | `bpf.CurrentPidTgid` |
| `ebpf.task.under_cgroup` | `bpf.CgroupArray.TaskUnder` |
| `ebpf.timer.callback` | `bpf.Timer.SetCallback` |
| `ebpf.timer.done` | `bpf.Timer.SetCallback` |
| `ebpf.timer.init` | `bpf.Timer.Init` |
| `ebpf.timer.set_callback` | `bpf.Timer.SetCallback` |
| `ebpf.timer.start` | `bpf.Timer.Start` |
| `ebpf.tp.buffer.load` | `bpf.RawTPWritableContext.Buffer` |
| `ebpf.tp.buffer.store` | `bpf.RawTPWritableContext.SetBuffer` |
| `ebpf.tp.field` | `bpf.TracepointContext.Event` |
| `ebpf.tp.field.copy` | copying a tracepoint [N]byte / [N]int8 event field `q.F = ctx.Event().G` (q is a checked map borrow or a ring buffer reservation) |
| `ebpf.uprobe.arg` | `bpf.UprobeArg`, `bpf.UprobeBuf`, `bpf.UprobeStr` |
| `ebpf.usdt.arg` | `bpf.USDTArg` |
| `ebpf.user.read` | `bpf.RingBuf.OutputBuf` |
| `ebpf.user.read_str` | `bpf.RingBuf.OutputStrOrDiscard`, `bpf.RingBuf.OutputStr` |
| `ebpf.user.str_at` | `bpf.UserStrArray.At` |
| `ebpf.user_ringbuf.callback` | `bpf.UserRingBuf.Drain` |
| `ebpf.user_ringbuf.done` | `bpf.UserRingBuf.Drain` |
| `ebpf.user_ringbuf.drain` | `bpf.UserRingBuf.Drain` |
| `ebpf.verdict` | `bpf.CgroupAllow`, `bpf.CgroupDeny`, `bpf.FlowContinue`, `bpf.FlowDrop`, `bpf.FlowOK`, `bpf.KprobeSessionRun`, `bpf.KprobeSessionSkipReturn`, `bpf.LSMAllow`, `bpf.LWTDrop`, `bpf.LWTOK`, `bpf.NFAccept`, `bpf.NFDrop`, `bpf.SKDrop`, `bpf.SKPass`, `bpf.Seg6Drop`, `bpf.Seg6OK`, `bpf.SocketDrop`, `bpf.SocketKeep`, `bpf.TCActOK`, `bpf.TCActPipe`, `bpf.TCActShot`, `bpf.TCDrop`, `bpf.TCPass`, `bpf.XDPAborted`, `bpf.XDPDrop`, `bpf.XDPPass`, `bpf.XDPTx`, a program's last `return <verdict constant>` |
| `ebpf.verdict.if` | `if c { return A }; return B` / `if c { return A } else { return B }` at the end of a program body |
| `ebpf.xdp.adjust_head` | `bpf.XDPContext.AdjustHead` |
| `ebpf.xdp.adjust_tail` | `bpf.XDPContext.AdjustTail` |
| `ebpf.yield` | the end of a checked branch (a Lookup's `p != nil`, ctx.Check's `ok`, Output) |
