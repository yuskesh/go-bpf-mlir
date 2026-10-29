package bpf

import (
	"reflect"

	"github.com/cilium/ebpf"
)

// Spin lock and timer (bpf-mlir's ebpf.spin.region and ebpf.timer.*). Both are record field types, and such a record is
// **only a bpf.Array value** (one lock or one timer per record — not both). The ops are **xdp programs only** (the range bpf-mlir's compiler supports).
// The kernel rejects a kprobe / uprobe program that uses a map of lock / timer records (the frontend stops it at generate time — fentry can use it).

// SpinLock is a record field type (struct bpf_spin_lock — 4 bytes). It cannot be read or written as a value, and can be written only as the argument of bpf.WithLock(&p.F, …) on the eBPF side.
// On the user side, Array.Get / Put always read and write with BPF_F_LOCK for a map whose value has a SpinLock (the kernel takes the same lock and copies the fields other than the lock
// — it does not interleave with the WithLock region on the eBPF side). The SpinLock field from Get is always 0.
type SpinLock struct{ _ uint32 }

// Timer is a record field type (struct bpf_timer — 16 bytes). It cannot be read or written as a value, and can be written only as the receiver of Init / SetCallback / Start on the eBPF side.
// **A user-side Put on a map whose value has a Timer is stopped by the frontend** — the kernel stops a running timer on a userspace update.
// Entries need no initialization: the kernel creates array entries as 0. Get can read (the Timer field is always 0).
type Timer struct{ _ [2]uint64 }

// WithLock is eBPF side only: a closed critical region that takes lock, runs f, and releases it (bpf-mlir's ebpf.spin.region — forgetting to unlock cannot happen by construction).
// In the shape `if p := M.Lookup(k); p != nil { bpf.WithLock(&p.Lock, func() { … }) }`, only in an xdp program body. f is written directly as a func literal,
// and inside it **only reads and writes of the same p's fields other than the lock, integer arithmetic, and local variables declared in f** — calls (including helpers, map operations and KtimeNs),
// if / for, return / break / goto / defer / panic, assignments to outer variables and other pointers are stopped by the frontend with a position (the verifier refuses helpers inside the lock).
func WithLock(lock *SpinLock, f func()) { panic(ebpfOnly("WithLock")) }

// Init is eBPF side only: initializes the timer with the monotonic clock (helper bpf_timer_init — the map is the map of the Lookup that returned t) and returns **the raw status**:
// 0 is success; the second and later calls give −EBUSY (−16) and the timer stays initialized. **SetCallback / Start can be written only inside the then of `if st := p.T.Init(); st == 0 { … }`**
// (the frontend stops it — starting every time without checking the status would restart the timer even after −EBUSY). A statement that discards the status is GB017.
func (t *Timer) Init() int64 { panic(ebpfOnly("Timer.Init")) }

// SetCallback is eBPF side only: sets the timer's callback to cb (helper bpf_timer_set_callback). cb is written directly as a `func name(v *V)` in the same package (V is the record
// holding the timer). The callback body may have only reads and writes of v's fields other than the timer, integer arithmetic, bpf.KtimeNs(), **if (with else and nesting)** and **its own timer's
// v.T.Start(ns)** (a periodic timer; Init / SetCallback cannot be written in the callback) (the kernel calls it when the timer fires — one callback is
// for the records of one map). Returns the raw status (a statement that discards it is GB017).
func (t *Timer) SetCallback(cb any) int64 { panic(ebpfOnly("Timer.SetCallback")) }

// Start is eBPF side only: starts the timer to fire after ns (relative nanoseconds) (helper bpf_timer_start, flags 0 — inside the then where the program's Init status is 0, or a restart of its own timer inside the timer's callback (a periodic timer)).
// One Start is one firing; repeating Start in the callback up to a limit makes a periodic timer (it stops at the map's last uref). Returns the raw status
// (a timer without a callback gives −EINVAL (−22). A statement that discards it is GB017).
func (t *Timer) Start(ns uint64) int64 { panic(ebpfOnly("Timer.Start")) }

// lockFlag is BPF_F_LOCK if V is a record with a SpinLock field (the kernel takes the same lock as WithLock on the eBPF side and copies the fields other than the lock),
// and 0 otherwise.
func lockFlag[F ~uint64](v reflect.Type) F {
	if v.Kind() != reflect.Struct {
		return 0
	}
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Type == reflect.TypeFor[SpinLock]() {
			return F(ebpf.LookupLock) // BPF_F_LOCK (the same value for lookup and update)
		}
	}
	return 0
}
