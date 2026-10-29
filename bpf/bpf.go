// Package bpf provides the types and functions for writing the eBPF side inside one Go program.
//
// eBPF-side functions (functions whose first parameter is *XDPContext, and the functions reachable from them) are translated by gobpf's frontend
// (`go tool gobpf`) into bpf-mlir's ebpf dialect. The Go compiler also compiles the same functions for user space,
// but eBPF-side-only functions and methods are stubs in user space and panic with a named message when called
// (the frontend stops calls from the user-space side at build time).
//
// Shared declarations (maps) are written once as package-level variables, and are used as maps on the eBPF side and as
// handles to the loaded maps on the user-space side.
package bpf

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// XDPContext is the context of an xdp program (struct xdp_md). A function whose first parameter has this type becomes an xdp program.
// There is no way to create a value — the kernel passes it.
type XDPContext struct{ _ [0]func() }

// XDPAction is the verdict of an xdp program.
type XDPAction uint32

// xdp verdicts (the same values as the UAPI enum xdp_action). Only the redirect_map terminator returns XDP_REDIRECT (outside this set).
const (
	XDPAborted XDPAction = 0
	XDPDrop    XDPAction = 1
	XDPPass    XDPAction = 2
	XDPTx      XDPAction = 3
)

// Key32 is the key type of array maps.
type Key32 interface{ ~uint32 }

// Array is the declaration of a BPF_MAP_TYPE_ARRAY map. Write it as a package-level variable:
//
//	var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}
//	var LastSeen = bpf.Array[uint32, Seen]{MaxEntries: 256} // Seen is a record
//
// V is a 32 / 64-bit integer or a record (a named struct in the same package). Go type constraints cannot express a struct, so
// V is any, and gobpf's frontend checks its shape at build time (others are GB009 / GB016). Record rules:
//   - a field is a fixed-width integer (uint8 to uint64, int8 to int64) or a fixed-length array of one. Every named field has an exported name and a `schema:"…"` tag
//   - implicit padding cannot be written — make holes explicit `_ [N]byte` (so that the byte layout is the same on the Go and BPF sides)
//   - fields are integers in CPU order (little endian). Convert packet network-order values to CPU order with Window.BE16 etc. before storing them
//
// **Assignment and += to a record field are not atomic** (load → compute → store). XDP runs on several CPUs at once, so += to a record field of a shared map
// races with updates from other CPUs and loses counts. To count, use AtomicAdd on an integer map, and use record fields for
// values where last-writer-wins is fine (the last seen length, time, state).
//
// The key is 0 to MaxEntries−1. **A constant key out of range is stopped by the frontend** (GB009), but **with a variable key out of range, Update / AtomicAdd silently do nothing**
// (Array operations do not return the kernel's −E2BIG — a known existing gap. Lookup gives nil, so the `p != nil` branch shows it).
// For a variable key, if the frontend can prove the bound (`k & 7`, `k % N`, a loop variable, a preceding clamp `if k >= N { k = N - 1 }`, etc.) it says nothing;
// otherwise it emits the Conditional diagnostic GB020 (generation does not stop — it remains in the go generate output and in a comment of the generated file).
// A future option: a strict flag that stops on Conditional (none yet).
type Array[K Key32, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

func ebpfOnly(what string) string {
	return fmt.Sprintf("bpf: %s is an eBPF-side operation and was called in user space (gobpf's frontend rejects this at build time — was the code generated without `go tool gobpf`?)", what)
}

// Lookup is eBPF side only: a pointer to the key's value (nil if none). Use it only in the shape `if p := m.Lookup(k); p != nil { … }`.
func (a *Array[K, V]) Lookup(k K) *V { panic(ebpfOnly("Array.Lookup")) }

// Update is eBPF side only: sets the key's value to v.
func (a *Array[K, V]) Update(k K, v V) { panic(ebpfOnly("Array.Update")) }

// AtomicAdd is eBPF side only: atomically adds d to the key's value (does nothing if there is no element).
func (a *Array[K, V]) AtomicAdd(k K, d V) { panic(ebpfOnly("Array.AtomicAdd")) }

// Get is user-space side only: reads the key's value from the loaded map.
// Before gobpf.Load or after Objects.Close it returns a named error.
func (a *Array[K, V]) Get(k K) (V, error) {
	var v V
	m, err := binding.Map(a, "Array.Get")
	if err != nil {
		return v, err
	}
	if err := m.LookupWithFlags(k, &v, lockFlag[ebpf.MapLookupFlags](reflect.TypeFor[V]())); err != nil { // a SpinLock record uses BPF_F_LOCK
		return v, fmt.Errorf("Array.Get: map %s key %v: %w", binding.Symbol(a), k, err)
	}
	return v, nil
}

// Put is user-space side only: sets the key's value in the loaded map to v.
// Before gobpf.Load or after Objects.Close it returns a named error.
func (a *Array[K, V]) Put(k K, v V) error {
	m, err := binding.Map(a, "Array.Put")
	if err != nil {
		return err
	}
	if err := m.Update(k, v, ebpf.UpdateAny|lockFlag[ebpf.MapUpdateFlags](reflect.TypeFor[V]())); err != nil { // a SpinLock record uses BPF_F_LOCK
		return fmt.Errorf("Array.Put: map %s key %v: %w", binding.Symbol(a), k, err)
	}
	return nil
}

// Window is a checked range of the packet (valid only inside ctx.Check's in_range). There is no way to create a value — ctx.Check passes it.
// Read indexes are constants, and the bytes read must be inside the window (i + width ≤ n) (the frontend checks this).
type Window struct{ _ [0]func() }

// Check is eBPF side only: (window, true) if the packet's [off, off+n) is in range. n is a positive constant.
// Use it only in the shape `if w, ok := ctx.Check(off, n); ok { … } [else { … }]`. The API has no read that returns 0 out of range.
//
// It can also be used in the body of a bounded loop (always unrolled) (a packet walk, for example examples/tcpopts). To leave the loop out of range, end the arm with break / continue
// (`} else { break }`). A variable off needs CAP_PERFMON for a non-root loader. **On a 6.6 kernel, the verifier's processed count rises sharply as the unroll count N
// grows** (in the TCP options walk, N = 8 is about 9 thousand and N = 28 is about 560 thousand — more than half of the 1M limit. 7.1 / 6.12 stay constant
// per iteration). If you target 6.6, aim for N at most 16 (tcpopts uses 16 — accepted on all three kernels), and if you go larger, check load on 6.6.
func (c *XDPContext) Check(off uint32, n uint32) (Window, bool) { panic(ebpfOnly("XDPContext.Check")) }

// U8 is byte i of the window.
func (w Window) U8(i uint32) uint8 { panic(ebpfOnly("Window.U8")) }

// BE16 is the big-endian 16 bits starting at byte i of the window (network order).
func (w Window) BE16(i uint32) uint16 { panic(ebpfOnly("Window.BE16")) }

// BE32 is big-endian 32 bits.
func (w Window) BE32(i uint32) uint32 { panic(ebpfOnly("Window.BE32")) }

// BE64 is big-endian 64 bits.
func (w Window) BE64(i uint32) uint64 { panic(ebpfOnly("Window.BE64")) }

// LE16 is little-endian 16 bits.
func (w Window) LE16(i uint32) uint16 { panic(ebpfOnly("Window.LE16")) }

// LE32 is little-endian 32 bits.
func (w Window) LE32(i uint32) uint32 { panic(ebpfOnly("Window.LE32")) }

// LE64 is little-endian 64 bits.
func (w Window) LE64(i uint32) uint64 { panic(ebpfOnly("Window.LE64")) }

// RingBuf is the declaration of a BPF_MAP_TYPE_RINGBUF map. V is a record (the same rules as bpf.Array records). Write it as a package-level variable:
//
//	var Events = bpf.RingBuf[Event]{MaxEntries: 1 << 16} // a power of 2, 4096 or more (a multiple of the kernel page)
//
// The eBPF side outputs one event with Output. The user-space side reads with gobpf.NewReader.
type RingBuf[V any] struct {
	// MaxEntries is the ring buffer size (bytes — a constant power of 2, 4096 or more. Written in the declaration's composite literal).
	MaxEntries uint32
}

// Output is eBPF side only: outputs v as a ring buffer event, and **the return value is whether the reservation succeeded and was submitted** (false means the ring buffer was
// full and the event was dropped). v is a record composite literal (`Events.Output(Event{…})`). It combines reservation, writing every byte and submit into one,
// and does not expose the reservation as a Go value (linearity is kept by construction).
//
// There are two ways to count dropped events (they can be combined):
//   - the return value: `if !Events.Output(v) { Stats.AtomicAdd(KDropped, 1) }` (the result of bpf-mlir's ringbuf.if_reserved)
//   - a drop counter: `Events.Output(v, bpf.CountDropsIn(Drops, 0))` atomically adds 1 to key 0 of the integer map Drops when dropped
//     (the key is a constant less than Drops' MaxEntries). This shape may stay a statement
//
// **A statement `Events.Output(v)` that uses neither the return value nor a counter is stopped by the frontend** (GB017 — there would be no way to count dropped events). If drops are fine,
// write `_ = Events.Output(v)` explicitly.
func (r *RingBuf[V]) Output(v V, drops ...DropCounter) bool { panic(ebpfOnly("RingBuf.Output")) }

// DropCounter is where Output counts dropped events (made by CountDropsIn — not passed around as a value).
type DropCounter struct{ _ [0]func() }

// CountDropsIn is eBPF side only: write it only in the position of Output's second argument (`Events.Output(v, bpf.CountDropsIn(Drops, 0))`).
// The map is passed by value (`Drops` — not `&Drops`): other map operations use the method receiver (`Drops.AtomicAdd(…)`), so the styles differ,
// but this keeps taking addresses on the user side limited to the arguments of gobpf.NewReader (the frontend accepts Drops only as a map variable in this argument position).
func CountDropsIn(m Array[uint32, uint64], key uint32) DropCounter { panic(ebpfOnly("CountDropsIn")) }

// AtomicAdd is eBPF side only: adds delta to a record field **atomically** (no result — the value before the add is not returned).
// addr is only `&p.F` — p is the checked record pointer of `if p := M.Lookup(k); p != nil { … }`, and F is a 32 / 64-bit integer field directly in the record
// whose offset is a multiple of its width (natural alignment — for example a uint64 field at an offset that is a multiple of 8). Array elements (`&p.Arr[i]`) are not accepted
// (the frontend stops them with GB021).
//
// Counting a record counter of a shared map (Array, Hash) on many CPUs without losing counts: `p.F += d` is load → add → store, and loses adds from another CPU
// writing the same record at the same time. On a per-CPU map `+=` is enough (AtomicAdd does no harm either).
// Which to use: for a map with integer values `M.AtomicAdd(k, d)`, for a record field `bpf.AtomicAdd(&p.F, d)` (bpf-mlir's
// ref.field.atomic_add).
func AtomicAdd[T ~uint32 | ~uint64 | ~int32 | ~int64](addr *T, delta T) { panic(ebpfOnly("AtomicAdd")) }

// FentryContext is the context of an fentry (tracing) program. A function whose first parameter has this type and that has no result becomes an fentry program,
// and the kernel function to attach to is written in the directive just before the function declaration:
//
//	//gobpf:fentry do_sys_poll
//	func onPoll(ctx *bpf.FentryContext) { … }
//
// The program runs at the kernel function's entry. Function arguments cannot be read (bpf-mlir's fentry has no argument op). There is no verdict (the return value is 0).
// Attach with gobpf.AttachFentry; a non-root loader needs CAP_BPF + CAP_PERFMON (see the non-root guide).
type FentryContext struct{ _ [0]func() }

// FexitContext is the context of an fexit (tracing) program. R is the return type of the attached kernel function (width and sign — an 8 / 16 / 32 / 64-bit
// integer). A function whose first parameter has this type and that has no result becomes an fexit program, and the attach target and the number of arguments are written in the directive just before the function declaration:
//
//	//gobpf:fexit bpf_fentry_test1 nargs=1
//	func onRet(ctx *bpf.FexitContext[int32]) { r := ctx.Ret(); … }
//
// The program runs after the kernel function returns. **If the signature (nargs and R) differs from the kernel function, the verifier silently accepts it and Ret's value is wrong** — the guard is
// the check before load (requirements retsig against the target BTF's FUNC_PROTO — done by gobpf.Load. LoadUnchecked does not check).
// Attach with gobpf.AttachFexit; a non-root loader needs CAP_BPF + CAP_PERFMON.
type FexitContext[R ~int8 | ~int16 | ~int32 | ~int64 | ~uint8 | ~uint16 | ~uint32 | ~uint64] struct{ _ [0]func() }

// Ret is eBPF side only: the return value of the attached kernel function (bpf-mlir's ebpf.ctx.retval — truncates context slot nargs to R's width).
func (c *FexitContext[R]) Ret() R { panic(ebpfOnly("FexitContext.Ret")) }

// CurrentPidTgid is eBPF side only: the current task's tgid << 32 | pid (helper get_current_pid_tgid). The upper 32 bits are the process (tgid),
// the lower 32 bits are the thread (pid) — `uint32(v >> 32)` / `uint32(v)`. It is meaningful in tracing programs (in XDP etc. the value is the interrupted task).
func CurrentPidTgid() uint64 { panic(ebpfOnly("CurrentPidTgid")) }

// KtimeNs is eBPF side only: the monotonic clock in ns (helper ktime_get_ns).
func KtimeNs() uint64 { panic(ebpfOnly("KtimeNs")) }

// CurrentComm is eBPF side only: the current task's name (helper get_current_comm — 16 bytes, NUL-padded). **It can be written only as the value of a [16]uint8 field
// in a record literal of a ring buffer Output** (`Events.Output(Ev{Pid: p, Comm: bpf.CurrentComm()})` — written directly into the reserved
// field — bpf-mlir's ebpf.task.comm).
//
// The helper's status is discarded (an exception to GB017): the kernel's bpf_get_current_comm (kernel/bpf/helpers.c — the same on 7.1.8, 6.12.111, 6.6.157)
// zeroes the buffer and returns −EINVAL only when `current` is NULL; otherwise it writes the name with strscpy_pad and returns 0 (size > 0 is guaranteed by
// the verifier). In a tracing program in task context current is never NULL, and even on failure the field is zero-filled (no uninitialized bytes are emitted).
func CurrentComm() [16]uint8 { panic(ebpfOnly("CurrentComm")) }

// errno constants — Linux errno values (the absolute values of BPF helpers' negative returns). The status of hash-family map operations is 0 or one of these negated
// (`if st == -bpf.EEXIST { … }`). Tests check the values against golang.org/x/sys/unix.
const (
	ENOENT = 2  // missing key (Replace / Delete — AddOrInit synthesizes this when the second lookup finds it absent)
	E2BIG  = 7  // table full (Insert / Update / AddOrInit)
	ENOMEM = 12 // kernel memory allocation failure
	EEXIST = 17 // key already exists (Insert)
)

// Hash is the declaration of a BPF_MAP_TYPE_HASH map. K is a fixed-width integer (32 / 64 bit) or a record, and V is a 32 / 64-bit integer or a record
// (the same rules as bpf.Array records). Write it as a package-level variable:
//
//	var Flows = bpf.Hash[FlowKey, uint64]{MaxEntries: 4096}
//
// eBPF-side operations **return a status (int64 — 0 or a negative errno), and an expression statement that discards it is stopped by the frontend** (an explicit `_ = M.Update(k, v)` is accepted).
// Record keys and values are written as composite literals (`Flows.Insert(FlowKey{…}, 1)`). The hash family has no AtomicAdd
// (because it does nothing for a missing key) — count with AddOrInit.
type Hash[K any, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// LRUHash is the declaration of a BPF_MAP_TYPE_LRU_HASH map. **When full, the kernel silently evicts old entries** — counted values can disappear
// (Insert / Update do not fail even when full). The operations are the same as Hash.
type LRUHash[K any, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// Lookup is eBPF side only: a pointer to the key's value (nil if none). Use it only in the shape `if p := m.Lookup(k); p != nil { … }`.
func (m *Hash[K, V]) Lookup(k K) *V { panic(ebpfOnly("Hash.Lookup")) }

// Update is eBPF side only: sets the key's value to v (creating it if missing — BPF_ANY). status is 0 or a negative errno (-E2BIG when the table is full).
func (m *Hash[K, V]) Update(k K, v V) int64 { panic(ebpfOnly("Hash.Update")) }

// Insert is eBPF side only: creates the key only if it is missing (BPF_NOEXIST). -EEXIST if it already exists.
func (m *Hash[K, V]) Insert(k K, v V) int64 { panic(ebpfOnly("Hash.Insert")) }

// Replace is eBPF side only: replaces only if the key exists (BPF_EXIST). -ENOENT if missing.
func (m *Hash[K, V]) Replace(k K, v V) int64 { panic(ebpfOnly("Hash.Replace")) }

// Delete is eBPF side only: deletes the key. -ENOENT if missing.
func (m *Hash[K, V]) Delete(k K) int64 { panic(ebpfOnly("Hash.Delete")) }

// AddOrInit is eBPF side only: atomically adds d to the key's value, creating the key with d if missing (V is integers only).
// It does not lose counts on many CPUs: lookup → if present an atomic add, if missing Insert (noexist), and if another CPU created it first (-EEXIST) look up again and add.
// status is 0 or a negative errno — -E2BIG when the table is full, and -ENOENT **synthesized by AddOrInit** when it was deleted right after creation (racing with Delete or LRU eviction).
// When status ≠ 0, d was not added.
func (m *Hash[K, V]) AddOrInit(k K, d V) int64 { panic(ebpfOnly("Hash.AddOrInit")) }

// Get is user-space side only: reads the key's value (a missing key is an error wrapping ErrKeyNotExist).
func (m *Hash[K, V]) Get(k K) (V, error) { return mapGet[K, V](m, "Hash.Get", k) }

// Put is user-space side only: sets the key's value to v (creating it if missing).
func (m *Hash[K, V]) Put(k K, v V) error { return mapPut(m, "Hash.Put", k, v) }

// Remove is user-space side only: deletes the key (the name differs from the eBPF side's Delete because of status versus error — the same as Update / Put).
func (m *Hash[K, V]) Remove(k K) error { return mapRemove(m, "Hash.Remove", k) }

// Iterate is user-space side only: an iterator that reads every entry. **Concurrent changes on the eBPF side (Insert / Delete, LRU eviction) can cause
// duplicates or omissions** (the kernel's get_next_key — the semantics of cilium's MapIterator).
func (m *Hash[K, V]) Iterate() *Iterator[K, V] { return mapIterate[K, V](m, "Hash.Iterate") }

// Lookup is eBPF side only (the same as Hash.Lookup).
func (m *LRUHash[K, V]) Lookup(k K) *V { panic(ebpfOnly("LRUHash.Lookup")) }

// Update is eBPF side only (the same as Hash.Update — when full it evicts an old entry and creates).
func (m *LRUHash[K, V]) Update(k K, v V) int64 { panic(ebpfOnly("LRUHash.Update")) }

// Insert is eBPF side only (the same as Hash.Insert).
func (m *LRUHash[K, V]) Insert(k K, v V) int64 { panic(ebpfOnly("LRUHash.Insert")) }

// Replace is eBPF side only (the same as Hash.Replace).
func (m *LRUHash[K, V]) Replace(k K, v V) int64 { panic(ebpfOnly("LRUHash.Replace")) }

// Delete is eBPF side only (the same as Hash.Delete).
func (m *LRUHash[K, V]) Delete(k K) int64 { panic(ebpfOnly("LRUHash.Delete")) }

// AddOrInit is eBPF side only (the same as Hash.AddOrInit — when full it evicts an old entry and creates, so -E2BIG does not occur).
func (m *LRUHash[K, V]) AddOrInit(k K, d V) int64 { panic(ebpfOnly("LRUHash.AddOrInit")) }

// Get is user-space side only (the same as Hash.Get).
func (m *LRUHash[K, V]) Get(k K) (V, error) { return mapGet[K, V](m, "LRUHash.Get", k) }

// Put is user-space side only (the same as Hash.Put).
func (m *LRUHash[K, V]) Put(k K, v V) error { return mapPut(m, "LRUHash.Put", k, v) }

// Remove is user-space side only (the same as Hash.Remove).
func (m *LRUHash[K, V]) Remove(k K) error { return mapRemove(m, "LRUHash.Remove", k) }

// Iterate is user-space side only (the same as Hash.Iterate).
func (m *LRUHash[K, V]) Iterate() *Iterator[K, V] { return mapIterate[K, V](m, "LRUHash.Iterate") }

// Iterator is the user-space iterator of hash-family maps (`for it.Next() { it.Key(), it.Value() }; it.Err()`).
type Iterator[K, V any] struct {
	it  *ebpf.MapIterator
	k   K
	v   V
	err error
}

// Next reads the next entry (false at the end or on an error — tell them apart with Err).
func (it *Iterator[K, V]) Next() bool {
	if it.err != nil {
		return false
	}
	return it.it.Next(&it.k, &it.v)
}

// Key is the current entry's key.
func (it *Iterator[K, V]) Key() K { return it.k }

// Value is the current entry's value.
func (it *Iterator[K, V]) Value() V { return it.v }

// Err is the iteration error (before load, after Close, or a kernel error).
func (it *Iterator[K, V]) Err() error {
	if it.err != nil {
		return it.err
	}
	return it.it.Err()
}

func mapGet[K, V any](key any, method string, k K) (V, error) {
	var v V
	m, err := binding.Map(key, method)
	if err != nil {
		return v, err
	}
	if err := m.Lookup(k, &v); err != nil {
		return v, fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(key), k, err)
	}
	return v, nil
}

func mapPut[K, V any](key any, method string, k K, v V) error {
	m, err := binding.Map(key, method)
	if err != nil {
		return err
	}
	if err := m.Put(k, v); err != nil {
		return fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(key), k, err)
	}
	return nil
}

func mapRemove[K any](key any, method string, k K) error {
	m, err := binding.Map(key, method)
	if err != nil {
		return err
	}
	if err := m.Delete(k); err != nil {
		return fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(key), k, err)
	}
	return nil
}

func mapIterate[K, V any](key any, method string) *Iterator[K, V] {
	m, err := binding.Map(key, method)
	if err != nil {
		return &Iterator[K, V]{err: err}
	}
	return &Iterator[K, V]{it: m.Iterate()}
}

// GobpfTypes is **an internal API of the gobpf runtime** (user code does not call it — hence the Gobpf name prefix): the Go types of the map's key and value.
// gobpf's check before load (which stops a build that changed only the Go declaration after generation) reads the map variable's types through it.
func (a *Array[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes).
func (m *Hash[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes).
func (m *LRUHash[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime — a ring buffer has no key (nil) — the value is the event type.
func (r *RingBuf[V]) GobpfTypes() (key, value reflect.Type) { return nil, reflect.TypeFor[V]() }

// PerCPUArray is the declaration of a BPF_MAP_TYPE_PERCPU_ARRAY map. It has **a separate value per CPU**, and eBPF-side operations read and write only the current CPU's
// slot — no two CPUs write the same slot at once, so **+= on a record field is correct without atomics** (+= on an Array record
// loses counts on many CPUs). A program does not move CPUs during a run (the test run's migrate_disable, XDP's softirq).
// Sharing the same map with a different kind of program (such as tracing that interrupts XDP on the same CPU) is outside the scope.
//
// User space reads per-CPU values (GetPerCPU — the slice length is the number of possible CPUs, and the slot of a CPU that is not online is 0). The user sums
// a record's fields:
//
//	vs, _ := PerProto.GetPerCPU(k)
//	var total Stats
//	for _, v := range vs {
//		total.Packets += v.Packets
//		total.Bytes += v.Bytes
//	}
type PerCPUArray[K Key32, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// PerCPUHash is the declaration of a BPF_MAP_TYPE_PERCPU_HASH map. The operations are the same as Hash (they return a status), and the value is per CPU.
// When an eBPF-side Update **creates a new element, the other CPUs' slots are 0**.
type PerCPUHash[K any, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// LRUPerCPUHash is the declaration of a BPF_MAP_TYPE_LRU_PERCPU_HASH map. When full it silently evicts old entries (the same as LRUHash).
type LRUPerCPUHash[K any, V any] struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// Lookup is eBPF side only: a pointer to the current CPU's slot (nil if none).
func (a *PerCPUArray[K, V]) Lookup(k K) *V { panic(ebpfOnly("PerCPUArray.Lookup")) }

// Update is eBPF side only: sets the current CPU's slot to v.
func (a *PerCPUArray[K, V]) Update(k K, v V) { panic(ebpfOnly("PerCPUArray.Update")) }

// AtomicAdd is eBPF side only: adds d to the current CPU's slot (on per-CPU maps an ordinary += is enough — no atomic is needed).
func (a *PerCPUArray[K, V]) AtomicAdd(k K, d V) { panic(ebpfOnly("PerCPUArray.AtomicAdd")) }

// GetPerCPU is user-space side only: the key's per-CPU values (the length is the number of possible CPUs).
func (a *PerCPUArray[K, V]) GetPerCPU(k K) ([]V, error) {
	return perCPUGet[K, V](a, "PerCPUArray.GetPerCPU", k)
}

// PutPerCPU is user-space side only: writes the key's per-CPU values (the length of vs is the number of possible CPUs).
func (a *PerCPUArray[K, V]) PutPerCPU(k K, vs []V) error {
	return perCPUPut(a, "PerCPUArray.PutPerCPU", k, vs)
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes).
func (a *PerCPUArray[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// Lookup is eBPF side only: a pointer to the current CPU's slot (nil if none).
func (m *PerCPUHash[K, V]) Lookup(k K) *V { panic(ebpfOnly("PerCPUHash.Lookup")) }

// Update is eBPF side only (the same status as Hash.Update — the current CPU's slot).
func (m *PerCPUHash[K, V]) Update(k K, v V) int64 { panic(ebpfOnly("PerCPUHash.Update")) }

// Insert is eBPF side only (the same as Hash.Insert).
func (m *PerCPUHash[K, V]) Insert(k K, v V) int64 { panic(ebpfOnly("PerCPUHash.Insert")) }

// Replace is eBPF side only (the same as Hash.Replace).
func (m *PerCPUHash[K, V]) Replace(k K, v V) int64 { panic(ebpfOnly("PerCPUHash.Replace")) }

// Delete is eBPF side only (the same as Hash.Delete — deletes the slots of every CPU).
func (m *PerCPUHash[K, V]) Delete(k K) int64 { panic(ebpfOnly("PerCPUHash.Delete")) }

// GetPerCPU is user-space side only (the same as PerCPUArray.GetPerCPU).
func (m *PerCPUHash[K, V]) GetPerCPU(k K) ([]V, error) {
	return perCPUGet[K, V](m, "PerCPUHash.GetPerCPU", k)
}

// PutPerCPU is user-space side only (the same as PerCPUArray.PutPerCPU).
func (m *PerCPUHash[K, V]) PutPerCPU(k K, vs []V) error {
	return perCPUPut(m, "PerCPUHash.PutPerCPU", k, vs)
}

// Remove is user-space side only (the same as Hash.Remove).
func (m *PerCPUHash[K, V]) Remove(k K) error { return mapRemove(m, "PerCPUHash.Remove", k) }

// Iterate is user-space side only: keys and per-CPU values (the same semantics as Hash.Iterate).
func (m *PerCPUHash[K, V]) Iterate() *Iterator[K, []V] {
	return mapIterate[K, []V](m, "PerCPUHash.Iterate")
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes).
func (m *PerCPUHash[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// Lookup is eBPF side only (the same as PerCPUHash.Lookup).
func (m *LRUPerCPUHash[K, V]) Lookup(k K) *V { panic(ebpfOnly("LRUPerCPUHash.Lookup")) }

// Update is eBPF side only (the same as PerCPUHash.Update — when full it evicts an old entry and creates).
func (m *LRUPerCPUHash[K, V]) Update(k K, v V) int64 { panic(ebpfOnly("LRUPerCPUHash.Update")) }

// Insert is eBPF side only (the same as PerCPUHash.Insert).
func (m *LRUPerCPUHash[K, V]) Insert(k K, v V) int64 { panic(ebpfOnly("LRUPerCPUHash.Insert")) }

// Replace is eBPF side only (the same as PerCPUHash.Replace).
func (m *LRUPerCPUHash[K, V]) Replace(k K, v V) int64 { panic(ebpfOnly("LRUPerCPUHash.Replace")) }

// Delete is eBPF side only (the same as PerCPUHash.Delete).
func (m *LRUPerCPUHash[K, V]) Delete(k K) int64 { panic(ebpfOnly("LRUPerCPUHash.Delete")) }

// GetPerCPU is user-space side only (the same as PerCPUArray.GetPerCPU).
func (m *LRUPerCPUHash[K, V]) GetPerCPU(k K) ([]V, error) {
	return perCPUGet[K, V](m, "LRUPerCPUHash.GetPerCPU", k)
}

// PutPerCPU is user-space side only (the same as PerCPUArray.PutPerCPU).
func (m *LRUPerCPUHash[K, V]) PutPerCPU(k K, vs []V) error {
	return perCPUPut(m, "LRUPerCPUHash.PutPerCPU", k, vs)
}

// Remove is user-space side only (the same as Hash.Remove).
func (m *LRUPerCPUHash[K, V]) Remove(k K) error { return mapRemove(m, "LRUPerCPUHash.Remove", k) }

// Iterate is user-space side only (the same as PerCPUHash.Iterate).
func (m *LRUPerCPUHash[K, V]) Iterate() *Iterator[K, []V] {
	return mapIterate[K, []V](m, "LRUPerCPUHash.Iterate")
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes).
func (m *LRUPerCPUHash[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[V]()
}

// SumPerCPU is the sum of integer per-CPU values (for the result of GetPerCPU). For records the user sums the fields (see the PerCPUArray doc).
func SumPerCPU[V ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~int8 | ~int16 | ~int32 | ~int64](vs []V) V {
	var s V
	for _, v := range vs {
		s += v
	}
	return s
}

func perCPUGet[K, V any](key any, method string, k K) ([]V, error) {
	m, err := binding.Map(key, method)
	if err != nil {
		return nil, err
	}
	var vs []V
	if err := m.Lookup(k, &vs); err != nil {
		return nil, fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(key), k, err)
	}
	return vs, nil
}

func perCPUPut[K, V any](key any, method string, k K, vs []V) error {
	m, err := binding.Map(key, method)
	if err != nil {
		return err
	}
	if err := m.Put(k, vs); err != nil {
		return fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(key), k, err)
	}
	return nil
}

// GobpfMapKind is an internal API of the gobpf runtime: the spelling of the map kind (checked against the type of the map row in the ELF's requirements — stops
// before load a build that changed only the map kind after generation (PerCPUArray → Array, etc.)).
func (a *Array[K, V]) GobpfMapKind() string { return "array" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (a *PerCPUArray[K, V]) GobpfMapKind() string { return "percpu_array" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *Hash[K, V]) GobpfMapKind() string { return "hash" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *LRUHash[K, V]) GobpfMapKind() string { return "lru_hash" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *PerCPUHash[K, V]) GobpfMapKind() string { return "percpu_hash" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *LRUPerCPUHash[K, V]) GobpfMapKind() string { return "lru_percpu_hash" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (r *RingBuf[V]) GobpfMapKind() string { return "ringbuf" }

// TCIngressContext is the context of a tcx ingress sched_cls program (struct __sk_buff). A function whose first parameter has this type becomes
// an ingress program (the direction is decided by the context type — not chosen at attach). There is no way to create a value — the kernel passes it.
type TCIngressContext struct{ _ [0]func() }

// TCEgressContext is the context of a tcx egress sched_cls program. A function whose first parameter has this type becomes an egress program.
type TCEgressContext struct{ _ [0]func() }

// TCAction is the verdict of a sched_cls program (values of the UAPI tcx_action_base). It is a different type from XDPAction — they cannot be mixed.
type TCAction int32

// sched_cls verdicts. Only the return value of ctx.Redirect / RedirectIf gives a redirect.
const (
	TCPass TCAction = 0 // TCX_PASS
	TCDrop TCAction = 2 // TCX_DROP
)

// Check is eBPF side only: (window, true) if the packet's [off, off+n) is in range. The same as XDPContext.Check (the sched_cls window is read only).
func (c *TCIngressContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("TCIngressContext.Check"))
}

// Check is eBPF side only (the same as TCIngressContext.Check).
func (c *TCEgressContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("TCEgressContext.Check"))
}

// Redirect is eBPF side only: **the return value is the requested action (TC_ACT_REDIRECT), not whether delivery succeeded** — even for an ifindex that does not exist
// it returns REDIRECT and the packet does not arrive. It requests sending the packet to the egress of ifindex (a value in the netns the program runs in).
// It can be written only as the program's last statement `return ctx.Redirect(ifindex)`.
func (c *TCIngressContext) Redirect(ifindex uint32) TCAction {
	panic(ebpfOnly("TCIngressContext.Redirect"))
}

// RedirectIf is eBPF side only: **the return value is the requested action, not whether delivery succeeded** (the same as Redirect). If cond is true it requests a redirect
// to ifindex; if false it returns otherwise (TCPass / TCDrop). It can be written only as the program's last statement `return ctx.RedirectIf(ok, ifindex, bpf.TCPass)`.
func (c *TCIngressContext) RedirectIf(cond bool, ifindex uint32, otherwise TCAction) TCAction {
	panic(ebpfOnly("TCIngressContext.RedirectIf"))
}

// Redirect is eBPF side only (the same as TCIngressContext.Redirect — the return value is the requested action, not whether delivery succeeded).
func (c *TCEgressContext) Redirect(ifindex uint32) TCAction {
	panic(ebpfOnly("TCEgressContext.Redirect"))
}

// RedirectIf is eBPF side only (the same as TCIngressContext.RedirectIf — the return value is the requested action, not whether delivery succeeded).
func (c *TCEgressContext) RedirectIf(cond bool, ifindex uint32, otherwise TCAction) TCAction {
	panic(ebpfOnly("TCEgressContext.RedirectIf"))
}

// ProgArray is the declaration of a BPF_MAP_TYPE_PROG_ARRAY map (tail calls). The key and value are fixed u32 (no type arguments). Write it as a package-level variable:
//
//	var Stages = bpf.ProgArray{MaxEntries: 4}
//
//	var _ = bpf.TailSlot(&Stages, 0, ParseIPv4) // xdp program ParseIPv4 in slot 0 — gobpf.Load sets it after load
//
// The eBPF side moves to a slot's program with TailCall / TailCallIf (xdp only). Slot declarations are set once at load,
// and undeclared slots stay empty (there is no API to replace them at run time — outside the scope). There is no operation to read or write prog_array from the eBPF side.
type ProgArray struct {
	// MaxEntries is the number of map entries (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// TailCall is eBPF side only: tail calls the program in slot i (does not return on success). **Write it only as a top-level statement of an xdp program body**;
// the statements after it (up to the final `return`) are the fallback on failure. There are 3 failures — an empty slot, an i at or above MaxEntries, the chain limit (33 — the kernel's
// MAX_TAIL_CALL_CNT. How it is counted differs by kernel version) — and the program cannot tell them apart.
//
//	Stages.TailCall(ctx, i)
//	Misses.AtomicAdd(0, 1) // fallback
//	return bpf.XDPPass
//
// To read the packet in the fallback, redo ctx.Check (an earlier check is invalid after a tail call attempt). One tail call per program
// (a TailCall inside the fallback, or inside an if or loop, is stopped by the frontend — GB023).
func (m *ProgArray) TailCall(ctx *XDPContext, i uint32) { panic(ebpfOnly("ProgArray.TailCall")) }

// TailCallIf is eBPF side only: if ok is true, the same as TailCall(ctx, i) (on failure, the fallback of the following statements); **if false, it returns otherwise without a tail call or the fallback**
// (bpf-mlir's `ebpf.tail_call … when %c else "<verdict>"`). The order matches sched_cls RedirectIf (ok, target, verdict when false). otherwise is a constant.
func (m *ProgArray) TailCallIf(ctx *XDPContext, ok bool, i uint32, otherwise XDPAction) {
	panic(ebpfOnly("ProgArray.TailCallIf"))
}

// Slot is the result of TailSlot (the value has no meaning — discard it with `var _ =`).
type Slot struct{ _ [0]func() }

// TailSlot is a prog_array slot declaration: puts xdp program prog in m's slot. **Write it only as `var _ = bpf.TailSlot(&M, slot, Prog)` at the top level of the package**
// (the frontend reads it statically and turns it into the schema's slots and requirements tailslot rows). slot is a constant less than MaxEntries, and prog is an xdp program
// function in the same package (a function value — not a name string). A double declaration of the same slot is stopped (GB023). It does nothing at run time — gobpf.Load sets it.
//
// The composite literal of ProgArray has no way to write slots because, when a slot's program tail calls into the same map, it would be a Go
// initialization cycle.
func TailSlot(m *ProgArray, slot uint32, prog func(*XDPContext) XDPAction) Slot { return Slot{} }

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key and value are u32.
func (m *ProgArray) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *ProgArray) GobpfMapKind() string { return "prog_array" }

// --- XDP packet rewriting ---

// SetU8 is eBPF side only: writes 1 byte at constant index i of the window (**xdp only** — writes to a sched_cls window are stopped by the frontend, GB025).
// The bytes written must be inside the window (i + width ≤ n) (the same as reads — GB014). Write it only as an expression statement.
func (w Window) SetU8(i uint32, v uint8) { panic(ebpfOnly("Window.SetU8")) }

// SetBE16 is eBPF side only: writes v in big endian (network order) (the same rules as SetU8).
func (w Window) SetBE16(i uint32, v uint16) { panic(ebpfOnly("Window.SetBE16")) }

// SetBE32 is eBPF side only: writes v in big endian.
func (w Window) SetBE32(i uint32, v uint32) { panic(ebpfOnly("Window.SetBE32")) }

// SetBE64 is eBPF side only: writes v in big endian.
func (w Window) SetBE64(i uint32, v uint64) { panic(ebpfOnly("Window.SetBE64")) }

// SetLE16 is eBPF side only: writes v in little endian.
func (w Window) SetLE16(i uint32, v uint16) { panic(ebpfOnly("Window.SetLE16")) }

// SetLE32 is eBPF side only: writes v in little endian.
func (w Window) SetLE32(i uint32, v uint32) { panic(ebpfOnly("Window.SetLE32")) }

// SetLE64 is eBPF side only: writes v in little endian.
func (w Window) SetLE64(i uint32, v uint64) { panic(ebpfOnly("Window.SetLE64")) }

// AdjustHead is eBPF side only: moves the start of the packet by delta bytes (positive trims, negative grows — the kernel checks the headroom) and returns the helper's **raw status**
// (0 or a negative errno — on failure −22 and the packet is unchanged). **An expression statement that discards the status is stopped by the frontend** (GB017 — make it explicit with `_ =`).
//
// **On success or failure, any Window obtained before becomes invalid** — later reads and writes are stopped by the frontend at the Go line (GB025). To read the packet again,
// redo ctx.Check. It cannot be written in a loop body (GB018).
func (c *XDPContext) AdjustHead(delta int32) int64 { panic(ebpfOnly("XDPContext.AdjustHead")) }

// AdjustTail is eBPF side only: moves the end of the packet by delta bytes — **shrinking only**: delta is a constant ≤ 0 (in bpf-mlir, growing depends on
// the driver's tailroom, which is not measured). The status and Window invalidation are the same as AdjustHead.
func (c *XDPContext) AdjustTail(delta int32) int64 { panic(ebpfOnly("XDPContext.AdjustTail")) }

// --- global variables (bpf-mlir's globals) ---

// ConfigInt is the value type of Config (an integer of 8 to 64 bits).
type ConfigInt interface {
	~uint8 | ~uint16 | ~uint32 | ~uint64 | ~int8 | ~int16 | ~int32 | ~int64
}

// GlobalInt is the value type of Global (a 32 / 64-bit integer — the width of BPF atomic adds).
type GlobalInt interface {
	~uint32 | ~uint64 | ~int32 | ~int64
}

// Config is the declaration of a **.rodata global variable** — a setting that user space sets before load (not a Go const — ifindex, thresholds, ports, etc.).
// Write it as a package-level variable (its name becomes the ELF symbol and the schema's global name):
//
//	var Port = bpf.Config[uint16]{}                 // Port.Set(v) is required before Load
//	var Verbose = bpf.Config[uint8]{Optional: true} // 0 if not Set
//
// The eBPF side reads it with Value (the verifier tracks the value set before load as a constant). User space Sets it **before** gobpf.Load — after load
// the kernel freezes .rodata, so Set is an error. **If a non-Optional Config is not Set before Load, Load stops with the Config's name** (rather than silently
// running with 0). If you mean 0, use Set(0) or Optional: true.
type Config[T ConfigInt] struct {
	// Optional allows a Config that is not Set (the value is 0). By default (false) a Config that is not Set is a Load error.
	Optional bool
}

// Value is eBPF side only: reads the setting (bpf-mlir's ebpf.global.load — one volatile read).
func (c *Config[T]) Value() T { panic(ebpfOnly("Config.Value")) }

// Set is the user-space side: decides the setting before Load (an error after Load — .rodata is frozen).
func (c *Config[T]) Set(v T) error { return binding.SetPending(c, "Config.Set", v) }

// Get is the user-space side: after Load the kernel's .rodata value, before Load the value Set (an error if not Set).
func (c *Config[T]) Get() (T, error) {
	var out T
	if v, err := binding.Variable(c, "Config.Get"); err == nil {
		err = v.Get(&out)
		return out, err
	}
	if p, ok := binding.Pending(c); ok {
		return p.(T), nil
	}
	return out, fmt.Errorf("Config.Get: the config is neither loaded nor set")
}

// GobpfGlobal is an internal API of the gobpf runtime: the section, the value type and Optional.
func (c *Config[T]) GobpfGlobal() (section string, t reflect.Type, optional bool) {
	return "rodata", reflect.TypeFor[T](), c.Optional
}

// Global is the declaration of a **.bss global variable** — a counter the eBPF side counts atomically and user space reads after load (without a map).
//
//	var Seen = bpf.Global[uint64]{}
//
// The eBPF side has Add (atomic — no lost counts on many CPUs) and Load (one volatile read — not acquire; ordering with concurrent Adds is not guaranteed).
// User space has Get (after load — reads while running are approximate). **User space has no Set** — so that run-time writes cannot race with
// eBPF-side Adds.
type Global[T GlobalInt] struct {
	// _ gives each Global variable a distinct address (Go may place variables of a zero-size struct at the same address. binding looks up a global by the variable's
	// pointer, so two Globals of the same T collided as a "double declaration").
	_ byte
}

// Add is eBPF side only: atomically adds d (bpf-mlir's ebpf.global.atomic_add — no result).
func (g *Global[T]) Add(d T) { panic(ebpfOnly("Global.Add")) }

// Load is eBPF side only: reads the value (one volatile read).
func (g *Global[T]) Load() T { panic(ebpfOnly("Global.Load")) }

// Get is the user-space side: reads the value after load.
func (g *Global[T]) Get() (T, error) {
	var out T
	v, err := binding.Variable(g, "Global.Get")
	if err != nil {
		return out, err
	}
	err = v.Get(&out)
	return out, err
}

// GobpfGlobal is an internal API of the gobpf runtime: the section and the value type.
func (g *Global[T]) GobpfGlobal() (section string, t reflect.Type, optional bool) {
	return "bss", reflect.TypeFor[T](), false
}
