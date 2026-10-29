// forkwatch is a tp_btf example on sched_process_fork: it counts new child processes and threads per parent process (tgid) and records the last child
// process's comm (a copy of the kernel char[16]), start_time (64 bit) and real_parent tgid (following a pointer with a nil check). The parent and child
// pid / tgid are task_struct fields read with CO-RE (a local kernel type Task — marked with bpf.Kernel). -pid goes into the .rodata Config
// (Optional — 0 means every process).
//
//	forkwatch [-pid N] [-duration 5s]   # attach and print the counts per parent tgid
//	forkwatch -selftest                 # start 3 child processes of its own and check the counts and the last child's pid
//	forkwatch -parse-only               # parse the embedded ELF without touching the kernel (no root needed)
//
// **It cannot be loaded on a 6.6 kernel** — the 6.6 verifier does not mark tracepoint arguments that can be NULL, and a NULL read silently becomes 0, so
// gobpf.Load stops with a named error (arg_nullable). Non-root needs CAP_BPF + CAP_PERFMON. Note: on 6.6 the NULL read is expected to be a kernel NULL dereference rather than a silent 0 (not confirmed at run time — see the note in bpf/tpbtf.go).
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Task is a local declaration of the kernel's task_struct (only the fields it reads — offsets are resolved from the kernel BTF at load time).
type Task struct {
	_          bpf.Kernel `kernel:"task_struct"`
	Pid        int32      `kernel:"pid"`
	Tgid       int32      `kernel:"tgid"`
	Start      uint64     `kernel:"start_time"`  // a 64-bit field (CLOCK_MONOTONIC ns)
	Comm       [16]byte   `kernel:"comm"`        // char[16] — copied into a record field (kfield.copy)
	RealParent *Task      `kernel:"real_parent"` // a pointer field — followed with `if rp := t.RealParent; rp != nil { … }`
}

// Info records the last child process (a copy of the kernel comm, start_time, the real_parent tgid).
type Info struct {
	Comm  [16]byte `schema:"comm"`
	Start uint64   `schema:"start"`
	PPid  int32    `schema:"ppid"` // the real_parent tgid (-1 if NULL)
	_     [4]byte
}

// Target is the parent tgid to watch (.rodata — 0 means all).
var Target = bpf.Config[uint32]{Optional: true}

var (
	// Procs is the number of child processes per parent tgid, Threads the number of threads.
	Procs   = bpf.Hash[uint32, uint64]{MaxEntries: 4096}
	Threads = bpf.Hash[uint32, uint64]{MaxEntries: 4096}
	// LastChild[0] is the pid of the last child process.
	LastChild = bpf.Array[uint32, uint32]{MaxEntries: 1}
	// Last[0] is the last child process's comm, start_time and real_parent tgid.
	Last = bpf.Array[uint32, Info]{MaxEntries: 1}
)

// OnFork is the eBPF side (a tp_btf program).
//
//gobpf:tp_btf sched_process_fork
func OnFork(ctx *bpf.TPBTFContext) {
	parent := bpf.TPArg[Task](ctx, 0)
	child := bpf.TPArg[Task](ctx, 1)
	ptgid := uint32(parent.Tgid)
	want := Target.Value()
	if want == 0 || ptgid == want {
		cpid := child.Pid
		ctgid := child.Tgid
		if cpid == ctgid {
			_ = Procs.AddOrInit(ptgid, 1) // a failure on a full table is not counted (an example — the status is discarded)
			LastChild.Update(0, uint32(cpid))
			if q := Last.Lookup(0); q != nil {
				q.Comm = child.Comm   // a 16-byte copy of the kernel char[16]
				q.Start = child.Start // a 64-bit field
				if rp := child.RealParent; rp != nil {
					q.PPid = rp.Tgid
				} else {
					q.PPid = -1
				}
			}
		} else {
			_ = Threads.AddOrInit(ptgid, 1)
		}
	}
}

func main() {
	pid := flag.Int("pid", 0, "parent tgid to watch (0 = all)")
	duration := flag.Duration("duration", 5*time.Second, "watch for this long, then print")
	selftest := flag.Bool("selftest", false, "start child processes of this process and check the counts")
	parseOnly := flag.Bool("parse-only", false, "parse the embedded ELF without touching the kernel")
	flag.Parse()

	if *parseOnly {
		spec, err := gobpf.LoadCollectionSpec()
		if err != nil {
			log.Fatalf("cannot parse the embedded ELF: %v", err)
		}
		fmt.Printf("parse-ok programs=%d maps=%d\n", len(spec.Programs), len(spec.Maps))
		return
	}
	if *selftest {
		*pid = os.Getpid()
	}
	if *pid != 0 {
		if err := Target.Set(uint32(*pid)); err != nil {
			log.Fatal(err)
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}
	objs, rest, err := gobpf.Load(livecaps.New())
	if err != nil {
		var te *gobpf.TargetError
		if errors.As(err, &te) {
			for _, u := range te.Unmet {
				if u.Kind == "arg_nullable" {
					fmt.Println("selftest result=refused (arg_nullable — this kernel's verifier does not mark NULL-able tracepoint arguments; tp_btf programs that read struct (pointer) arguments cannot load here — bpf-mlir v1.1.0)")
					os.Exit(1)
				}
			}
		}
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	for _, u := range rest {
		if u.Kind != "arg_nullable_unknown" { // on a kernel that marks NULL-able arguments, the verifier decides the read (do not stop)
			log.Printf("undetermined (loaded anyway): %s", u.String())
		}
	}
	l, err := gobpf.AttachTPBTF(objs, OnFork)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	if *selftest {
		os.Exit(runSelftest())
	}
	time.Sleep(*duration)
	it := Procs.Iterate()
	for it.Next() {
		th, _ := Threads.Get(it.Key())
		fmt.Printf("parent tgid=%d processes=%d threads=%d\n", it.Key(), it.Value(), th)
	}
	if err := it.Err(); err != nil {
		log.Print(err)
	}
}

func runSelftest() int {
	me := uint32(os.Getpid())
	before, _ := Procs.Get(me)
	var last int
	const n = 3
	t0 := monotonicNs()
	for i := 0; i < n; i++ {
		c := exec.Command("/bin/true")
		if err := c.Run(); err != nil {
			log.Print(err)
			return 1
		}
		last = c.Process.Pid
	}
	t1 := monotonicNs()
	after, _ := Procs.Get(me)
	lc, _ := LastChild.Get(0)
	info, _ := Last.Get(0)
	// The Go runtime may fork once to probe pidfd before the first exec — the count is at least n and at most n+1.
	d := after - before
	// The last child's comm is a copy of the parent's comm at fork time, start_time lies between CLOCK_MONOTONIC before and after starting the child, real_parent is this process.
	comm, _ := os.ReadFile("/proc/self/comm")
	var want [16]byte
	copy(want[:15], bytes.TrimRight(comm, "\n"))
	infoOK := info.Comm == want && info.Start >= t0 && info.Start <= t1 && info.PPid == int32(me)
	ok := d >= n && d <= n+1 && int(lc) == last && infoOK
	fmt.Printf("selftest processes=+%d (started %d) last_child=%d/%d comm=%q ppid=%d start_in_window=%v result=%s\n", d, n, lc, last, bytes.TrimRight(info.Comm[:], "\x00"), info.PPid, info.Start >= t0 && info.Start <= t1, map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}

// monotonicNs is CLOCK_MONOTONIC in ns (the same clock as the kernel task's start_time).
func monotonicNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}
