// syscount is an example with an fentry program that counts calls to the kernel function do_sys_poll (poll(2) / ppoll(2)) per process (tgid),
// and a ring buffer that outputs the calls of a chosen process as events (pid, time, task name), written in one Go program with the user-space side.
//
//	syscount [-duration 5s] [-top 10] [-watch <tgid>]  # attach and print the top counts per tgid (and the events of the -watch process)
//	syscount -selftest                                 # compare the counts and events from a test run and poll(2) on its own thread with the expected values
//	syscount -parse-only                               # parse the embedded ELF without touching the kernel (no root needed)
//
// A non-root loader needs CAP_BPF + CAP_PERFMON (fentry — docs/nonroot.md).
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Ev is a poll event of the -watch process.
type Ev struct {
	PidTgid uint64    `schema:"pid_tgid"`
	Ns      uint64    `schema:"ns"`
	Comm    [16]uint8 `schema:"comm"`
}

// Calls is the number of do_sys_poll calls per tgid.
var Calls = bpf.Hash[uint32, uint64]{MaxEntries: 4096}

// Watch[0] is the tgid to output events for (0 outputs none).
var Watch = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Stat indexes: 0 the selftest trigger count, 1 failures to add to Calls (hash full), 2 Events Output returning false, 3 failures to add to Errnos.
var Stat = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Rets is the distribution of do_sys_poll return values (fexit): 0 for 0 (no ready fd), 1 for 1, 2 for 2 or more, 3 for negative (an error — the errno goes to Errnos).
// If Watch[0] is 0 it counts every process, otherwise only that tgid.
var Rets = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Errnos counts negative return values per errno (−return value).
var Errnos = bpf.Hash[uint32, uint64]{MaxEntries: 64}

var Events = bpf.RingBuf[Ev]{MaxEntries: 1 << 16}

//gobpf:fentry do_sys_poll
func onPoll(ctx *bpf.FentryContext) {
	pt := bpf.CurrentPidTgid()
	tgid := uint32(pt >> 32)
	if st := Calls.AddOrInit(tgid, 1); st != 0 {
		Stat.AtomicAdd(1, 1) // hash full (-E2BIG and the like) — not counted
	}
	w := uint64(0)
	if p := Watch.Lookup(0); p != nil {
		w = *p
	}
	if w != 0 && uint64(tgid) == w {
		if !Events.Output(Ev{PidTgid: pt, Ns: bpf.KtimeNs(), Comm: bpf.CurrentComm()}) {
			Stat.AtomicAdd(2, 1)
		}
	}
}

// onPollRet counts the return values of do_sys_poll (fexit — `int do_sys_poll(struct pollfd __user *, unsigned int, struct timespec64 *)` — nargs 3, int).
// The pre-load check (retsig) checks the signature against the target BTF (a mistake would become a silent value, so the check is the only guard).
//
//gobpf:fexit do_sys_poll nargs=3
func onPollRet(ctx *bpf.FexitContext[int32]) {
	r := ctx.Ret()
	w := uint64(0)
	if p := Watch.Lookup(0); p != nil {
		w = *p
	}
	pt := bpf.CurrentPidTgid()
	if w == 0 || pt>>32 == w {
		if r < 0 {
			Rets.AtomicAdd(3, 1)
			if st := Errnos.AddOrInit(uint32(-r), 1); st != 0 {
				Stat.AtomicAdd(3, 1)
			}
		} else if r >= 2 {
			Rets.AtomicAdd(2, 1)
		} else if r == 1 {
			Rets.AtomicAdd(1, 1)
		} else {
			Rets.AtomicAdd(0, 1)
		}
	}
}

// onSelftest is the deterministic selftest trigger: it counts on bpf_fentry_test1, which the kernel's tracing test run calls.
//
//gobpf:fentry bpf_fentry_test1
func onSelftest(ctx *bpf.FentryContext) {
	Stat.AtomicAdd(0, 1)
}

func main() {
	duration := flag.Duration("duration", 5*time.Second, "count for this long")
	top := flag.Int("top", 10, "number of processes to show")
	watch := flag.Int("watch", 0, "tgid of the process to emit events for (0 = none)")
	selftest := flag.Bool("selftest", false, "compare the counts and events from a test run and poll(2) on this thread with the expected values")
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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}
	objs, rest, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	if len(rest) > 0 {
		// Unknowns that do not stop the load (the LiveCaps of bpf-mlir v0.7.0 answers the tracing helpers and retsig definitely — normally none appear).
		log.Printf("undetermined (loaded anyway): %d requirement row(s) could not be probed on this target", len(rest))
	}
	if *selftest {
		os.Exit(runSelftest(objs))
	}
	l, err := gobpf.AttachFentry(objs, onPoll)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer l.Close()
	lr, err := gobpf.AttachFexit(objs, onPollRet)
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer lr.Close()
	if *watch != 0 {
		if err := Watch.Put(0, uint64(*watch)); err != nil {
			log.Fatal(err)
		}
		go printEvents()
	}
	time.Sleep(*duration)
	printTop(*top)
}

type row struct {
	tgid  uint32
	calls uint64
}

func printTop(n int) {
	var rows []row
	it := Calls.Iterate()
	for it.Next() {
		rows = append(rows, row{it.Key(), it.Value()})
	}
	if err := it.Err(); err != nil {
		log.Printf("iterate: %v", err)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].calls > rows[j].calls || (rows[i].calls == rows[j].calls && rows[i].tgid < rows[j].tgid)
	})
	for i, r := range rows {
		if i == n {
			break
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", r.tgid))
		fmt.Printf("tgid %d (%s) calls %d\n", r.tgid, strings.TrimSpace(string(comm)), r.calls)
	}
	lost, _ := Stat.Get(1)
	fmt.Printf("processes %d, not counted (hash full) %d\n", len(rows), lost)
	printReturns()
}

func printEvents() {
	rd, err := gobpf.NewReader(&Events)
	if err != nil {
		log.Print(err)
		return
	}
	for {
		ev, err := rd.Read()
		if err != nil {
			return
		}
		fmt.Printf("event pid %d tgid %d comm %s ns %d\n", uint32(ev.PidTgid), ev.PidTgid>>32, bytes.TrimRight(ev.Comm[:], "\x00"), ev.Ns)
	}
}

// runSelftest runs two triggers on its own thread:
//  1. onSelftest (bpf_fentry_test1) — n test runs of onSelftest → Stat[0] grows by n
//  2. onPoll (do_sys_poll) — m poll(2) calls on a pinned thread → Calls[own tgid] grows by m, and with itself in Watch there are m events (pid == tid, comm)
func runSelftest(objs *gobpf.Objects) int {
	ls, err := gobpf.AttachFentry(objs, onSelftest)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer ls.Close()
	lp, err := gobpf.AttachFentry(objs, onPoll)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer lp.Close()
	lr, err := gobpf.AttachFexit(objs, onPollRet)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer lr.Close()
	var pipes [2][2]int
	for i := range pipes {
		if err := unix.Pipe(pipes[i][:]); err != nil {
			log.Print(err)
			return 1
		}
		defer unix.Close(pipes[i][0])
		defer unix.Close(pipes[i][1])
		unix.Write(pipes[i][1], []byte{1})
	}
	// Rets counts every process while Watch[0] is 0 — narrow to its own tgid first while taking the distribution difference (do not mix in other processes' polls).
	Watch.Put(0, uint64(unix.Getpid()))
	var retsBefore [4]uint64
	for k := range retsBefore {
		retsBefore[k], _ = Rets.Get(uint32(k))
	}
	efaultBefore, _ := Errnos.Get(uint32(unix.EFAULT))
	rd, err := gobpf.NewReader(&Events)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer rd.Close()
	prog, err := objs.Program(onSelftest)
	if err != nil {
		log.Print(err)
		return 1
	}
	const n, m = 20, 15
	ok := true
	before, _ := Stat.Get(0)
	for i := 0; i < n; i++ {
		if _, err := prog.Run(&ebpf.RunOptions{}); err != nil {
			log.Printf("test run: %v", err)
			return 1
		}
	}
	after, _ := Stat.Get(0)
	if after-before != n {
		ok = false
		fmt.Printf("mismatch selftest trigger: %d, want %d\n", after-before, n)
	}
	tgid := uint32(unix.Getpid())
	callsBefore, _ := Calls.Get(tgid) // 0 if absent (the error is ignored — the first call)
	var tid int
	var comm string
	done := make(chan struct{})
	go func() { // the goroutine ends with the thread still locked (Go discards the pinned thread)
		defer close(done)
		runtime.LockOSThread()
		var set unix.CPUSet
		set.Set(0)
		unix.SchedSetaffinity(0, &set)
		tid = unix.Gettid()
		c, _ := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/comm", tid))
		comm = strings.TrimSpace(string(c))
		for i := 0; i < m; i++ {
			unix.Poll(nil, 0) // returns 0
		}
		// The fexit return value distribution: one ready pipe (1), two (2), a pollfd at an unreadable address (-EFAULT).
		unix.Poll([]unix.PollFd{{Fd: int32(pipes[0][0]), Events: unix.POLLIN}}, 0)
		unix.Poll([]unix.PollFd{{Fd: int32(pipes[0][0]), Events: unix.POLLIN}, {Fd: int32(pipes[1][0]), Events: unix.POLLIN}}, 0)
		unix.Syscall(unix.SYS_POLL, 1, 1, 0)
	}()
	<-done
	callsAfter, _ := Calls.Get(tgid)
	var evs []Ev
	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		ev, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			log.Print(err)
			return 1
		}
		evs = append(evs, ev)
	}
	good := 0
	for _, ev := range evs {
		if uint32(ev.PidTgid) == uint32(tid) && uint32(ev.PidTgid>>32) == tgid && string(bytes.TrimRight(ev.Comm[:], "\x00")) == comm {
			good++
		}
	}
	// Calls counts the polls of every thread of this process (the Go runtime does not use poll(2)). Events are output only while Watch is set.
	const polls = m + 3
	if callsAfter-callsBefore != polls || len(evs) != polls || good != polls {
		ok = false
		fmt.Printf("mismatch poll: calls +%d, events %d (matching %d), want %d\n", callsAfter-callsBefore, len(evs), good, polls)
	}
	var rets [4]uint64
	for k := range rets {
		v, _ := Rets.Get(uint32(k))
		rets[k] = v - retsBefore[k]
	}
	efault, _ := Errnos.Get(uint32(unix.EFAULT))
	Watch.Put(0, 0)
	if rets != [4]uint64{m, 1, 1, 1} || efault-efaultBefore != 1 {
		ok = false
		fmt.Printf("mismatch returns: 0=+%d 1=+%d 2+=+%d negative=+%d errno%d=+%d, want %d 1 1 1 and 1\n", rets[0], rets[1], rets[2], rets[3], unix.EFAULT, efault-efaultBefore, m)
	}
	fmt.Printf("selftest returns 0=+%d 1=+%d 2+=+%d negative=+%d (errno%d +%d)\n", rets[0], rets[1], rets[2], rets[3], unix.EFAULT, efault-efaultBefore)
	fmt.Printf("selftest trigger=%d/%d polls=%d calls=+%d events=%d matching=%d comm=%q\n", after-before, n, polls, callsAfter-callsBefore, len(evs), good, comm)
	fmt.Printf("selftest result=%s\n", map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}

var _ link.Link // link is the type of the AttachFentry result (an explicit import)

// printReturns prints the distribution of do_sys_poll return values and the counts per errno (fexit).
func printReturns() {
	var r [4]uint64
	for k := range r {
		r[k], _ = Rets.Get(uint32(k))
	}
	fmt.Printf("poll returns: 0=%d 1=%d 2+=%d negative=%d", r[0], r[1], r[2], r[3])
	it := Errnos.Iterate()
	for it.Next() {
		fmt.Printf(" errno%d=%d", it.Key(), it.Value())
	}
	fmt.Println()
}
