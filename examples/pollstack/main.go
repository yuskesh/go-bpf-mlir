// pollstack is an fentry example on the entry of the kernel function do_sys_poll (poll(2) / ppoll(2)): it takes the id of the caller's kernel stack
// (bpf.StackTrace) and outputs events through a perf event array (bpf.PerfEventArray). The user-space side reads the events with a reader and turns
// the stacks into names with Stacks.Get and /proc/kallsyms. -pid goes into the .rodata Config (Optional — 0 means every process).
//
//	pollstack [-pid N] [-duration 5s]   # attach and print the events and stacks
//	pollstack -selftest                 # call poll(2) 20 times on its own thread and check the event count, thread, same stack id and lost 0
//	pollstack -parse-only               # parse the embedded ELF without touching the kernel (no root needed)
//
// The perf reader is opened before attach (gobpf.AttachFentry stops a program that outputs to a perf map with no reader). Non-root needs CAP_BPF + CAP_PERFMON
// (kallsyms addresses look like 0 to non-root — then the addresses are printed as they are).
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Event is one poll call (24 bytes). Stack is the raw Stacks.KernelID status (an id or a negative errno).
type Event struct {
	Pid   uint32 `schema:"pid"`
	Tgid  uint32 `schema:"tgid"`
	Ns    uint64 `schema:"ns"`
	Stack int64  `schema:"stack"`
}

// Target is the tgid to watch (.rodata — 0 means every process).
var Target = bpf.Config[uint32]{Optional: true}

var (
	Stacks = bpf.StackTrace{MaxEntries: 1024, Depth: 32}
	Events = bpf.PerfEventArray[Event]{}
	// Drops[0] counts Output failures (a CPU with no reader, overflow), Drops[1] KernelID failures.
	Drops = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

// OnPoll is the eBPF side (an fentry program).
//
//gobpf:fentry do_sys_poll
func OnPoll(ctx *bpf.FentryContext) {
	pt := bpf.CurrentPidTgid()
	tg := uint32(pt >> 32)
	want := Target.Value()
	if want == 0 || tg == want {
		st := Stacks.KernelID(ctx, 0)
		if st < 0 {
			Drops.AtomicAdd(1, 1)
		}
		if Events.Output(ctx, Event{Pid: uint32(pt), Tgid: tg, Ns: bpf.KtimeNs(), Stack: st}) != 0 {
			Drops.AtomicAdd(0, 1)
		}
	}
}

func main() {
	pid := flag.Int("pid", 0, "tgid to watch (0 = all)")
	duration := flag.Duration("duration", 5*time.Second, "read for this long, then exit")
	selftest := flag.Bool("selftest", false, "count this process's poll(2) calls and check them")
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
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	for _, u := range rest {
		log.Printf("undetermined (loaded anyway): %s", u.String())
	}
	rd, err := gobpf.NewPerfReader(&Events, 16) // before attach
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	l, err := gobpf.AttachFentry(objs, OnPoll)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	if *selftest {
		os.Exit(runSelftest(rd))
	}
	syms := loadKallsyms()
	deadline := time.Now().Add(*duration)
	seen := map[int64]bool{}
	for time.Now().Before(deadline) {
		rd.SetDeadline(deadline)
		r, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if r.Lost > 0 {
			fmt.Printf("lost %d events on cpu %d\n", r.Lost, r.CPU)
			continue
		}
		e := r.Value
		fmt.Printf("poll pid=%d tgid=%d cpu=%d stack=%d\n", e.Pid, e.Tgid, r.CPU, e.Stack)
		if e.Stack >= 0 && !seen[e.Stack] {
			seen[e.Stack] = true
			printStack(e.Stack, syms)
		}
	}
	d0, _ := Drops.Get(0)
	d1, _ := Drops.Get(1)
	fmt.Printf("drops output=%d stack=%d lost=%d\n", d0, d1, rd.Lost())
}

// kallsyms returns the text symbols of /proc/kallsyms (in address order). It returns nil if every address is 0 (not root).
type kallsyms struct {
	as []uint64
	ns []string
}

func loadKallsyms() *kallsyms {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil
	}
	defer f.Close()
	k := &kallsyms{}
	type sym struct {
		a uint64
		n string
	}
	var ss []sym
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || (fs[1] != "t" && fs[1] != "T") {
			continue
		}
		if a, _ := strconv.ParseUint(fs[0], 16, 64); a != 0 {
			ss = append(ss, sym{a, fs[2]})
		}
	}
	if len(ss) == 0 {
		return nil
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i].a < ss[j].a })
	for _, s := range ss {
		k.as, k.ns = append(k.as, s.a), append(k.ns, s.n)
	}
	return k
}

func (k *kallsyms) name(ip uint64) string {
	if k == nil {
		return fmt.Sprintf("%#x", ip)
	}
	i := sort.Search(len(k.as), func(i int) bool { return k.as[i] > ip }) - 1
	if i < 0 {
		return fmt.Sprintf("%#x", ip)
	}
	return fmt.Sprintf("%s+%#x", k.ns[i], ip-k.as[i])
}

// stackNames returns the frame names of the stack with the id (innermost first — frame 0 is the return address of the KernelID call inside the eBPF program).
func stackNames(id int64, syms *kallsyms) ([]string, error) {
	ips, err := Stacks.Get(uint32(id))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ip := range ips {
		out = append(out, syms.name(ip))
	}
	return out, nil
}

func printStack(id int64, syms *kallsyms) {
	names, err := stackNames(id, syms)
	if err != nil {
		fmt.Printf("  stack %d: %v\n", id, err)
		return
	}
	for i, n := range names {
		fmt.Printf("  #%d %s\n", i, n)
	}
}

func runSelftest(rd *gobpf.PerfReader[Event]) int {
	const n = 20
	// poll(2) n times on one OS thread (EINTR also counts as one — fentry runs before EINTR is returned; no retry). The goroutine ends with the
	// thread still locked (Go then discards that thread, so the pinned thread never returns to the pool).
	type res struct {
		tid int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		tid := unix.Gettid()
		for i := 0; i < n; i++ {
			if _, err := unix.Poll(nil, 0); err != nil && !errors.Is(err, unix.EINTR) {
				ch <- res{tid, err}
				return
			}
		}
		ch <- res{tid, nil}
	}()
	r := <-ch
	if r.err != nil {
		log.Print(r.err)
		return 1
	}
	var mine []Event
	end := time.Now().Add(2 * time.Second)
	for len(mine) < n && time.Now().Before(end) {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			log.Print(err)
			return 1
		}
		if rec.Lost == 0 && rec.Value.Pid == uint32(r.tid) {
			mine = append(mine, rec.Value)
		}
	}
	ids := map[int64]bool{}
	for _, e := range mine {
		ids[e.Stack] = true
	}
	var id int64 = -1
	for k := range ids {
		id = k
	}
	d0, _ := Drops.Get(0)
	d1, _ := Drops.Get(1)
	syms := loadKallsyms()
	names, gerr := []string(nil), error(nil)
	if id >= 0 {
		names, gerr = stackNames(id, syms)
	}
	through := "unchecked (kallsyms hidden)"
	if syms != nil {
		through = "missing"
		for _, s := range names {
			if strings.HasPrefix(s, "do_sys_poll+") {
				through = "ok"
			}
		}
	}
	for i, s := range names {
		fmt.Printf("  #%d %s\n", i, s)
	}
	ok := len(mine) == n && len(ids) == 1 && id >= 0 && gerr == nil && len(names) > 1 && d0 == 0 && d1 == 0 && rd.Lost() == 0 && through != "missing"
	fmt.Printf("selftest events=%d/%d tid=%d stack_ids=%d frames=%d do_sys_poll=%s drops=%d/%d lost=%d result=%s\n",
		len(mine), n, r.tid, len(ids), len(names), through, d0, d1, rd.Lost(), map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}
