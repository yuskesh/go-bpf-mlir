// greetwatch is a **uprobe** example on the entry of greet(const char *name, uint32_t n) in another binary (target/greeter — a C program): it
// outputs the call number and the name string to a ring buffer (bpf.UprobeArg and RingBuf.OutputStr). It also records the caller's **user stack**
// (an IP stack — bpf.StackTrace.UserID, and a build id stack — bpf.StackBuildID.UserID), and the user-space side prints the depth and per-element status counts.
//
//	greetwatch -target <greeter path> [-pid N] [-duration 5s]   # attach and print the greet calls
//	greetwatch -selftest [-target <path>]                          # start greeter and check the events against the stdin lines
//	greetwatch -parse-only                                         # parse the embedded ELF without touching the kernel (no root needed)
//
// The directive's path (target/greeter) is used only at generate time (the sha256 and the symbol, calling convention and argument types are checked). **The path and PID at
// run time are this program's input** — unless the greeter has the same hash as the build seen at generate time, gobpf.Load stops with a named error. **Its own (greetwatch)
// binary cannot be the target** (the hash would be circular). Non-root needs CAP_SYS_ADMIN (+ CAP_BPF).
//
// **Signs of a target without frame pointers**: on x86_64 the user stack walk uses only frame pointers. greeter is a default clang -O1 build
// (no frame pointers, no GNU build id), so after #0 (the greet entry) the stack either ends at depth 1 or follows the rbp value the caller uses as a general register into **fake frames**
// (addresses outside executable mappings — they can also show as status 1 in the build id stack). This example reports "depth 1 or a frame outside r-x" as the sign —
// if you need the caller chain, rebuild the target with `-fno-omit-frame-pointer` (and `-Wl,--build-id` if you need the build id stack).
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Greeting is the event for a greet call (OutputStr writes Name with user.read_str — truncated to 32 bytes). Stack / Build are user stack ids or
// a negative errno (the raw UserID status), Pid is the calling process's tgid (the user-space side looks up where frames are in /proc/<pid>/maps).
// Status is the read_str status written by OutputStr: negative means the read failed — the kernel fills Name with 0, so without Status it cannot be
// told apart from an empty string (the reader does not use Name of an event with Status < 0).
type Greeting struct {
	Stack  int64     `schema:"stack"`
	Build  int64     `schema:"build"`
	Pid    uint32    `schema:"pid"`
	N      uint32    `schema:"n"`
	Name   [32]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

// Greetings holds the events.
var Greetings = bpf.RingBuf[Greeting]{MaxEntries: 1 << 16}

// Stats: 0 the number of calls, 1 the number of read_str failures (st < 0), 2 the number of reservation failures.
var Stats = bpf.Array[uint32, uint64]{MaxEntries: 3}

// Stacks holds the IP user stacks of greet calls, Builds the build id user stacks.
var (
	Stacks = bpf.StackTrace{MaxEntries: 256, Depth: 32}
	Builds = bpf.StackBuildID{MaxEntries: 256, Depth: 32}
)

// OnGreet is the eBPF side (a uprobe program).
//
//gobpf:uprobe target/greeter greet
func OnGreet(ctx *bpf.UprobeContext) {
	Stats.AtomicAdd(0, 1)
	stack := Stacks.UserIDReuse(ctx, 0)
	build := Builds.UserIDReuse(ctx, 0)
	st, ok := Greetings.OutputStr(Greeting{Stack: stack, Build: build, Pid: uint32(bpf.CurrentPidTgid() >> 32), N: bpf.UprobeArg[uint32](ctx, 2)}, bpf.UprobeStr(ctx, 1))
	if !ok {
		Stats.AtomicAdd(2, 1)
	} else if st < 0 {
		Stats.AtomicAdd(1, 1)
	}
}

func main() {
	target := flag.String("target", "examples/greetwatch/target/greeter", "path of the greeter binary at run time (it must be the same build as at generate time — checked by hash)")
	pid := flag.Int("pid", 0, "process to attach to (0 = all)")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "start the greeter and check")
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
	objs, rest, err := gobpf.Load(livecaps.New(), gobpf.WithUprobeTarget(OnGreet, *target))
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	for _, u := range rest {
		log.Printf("undetermined (loaded anyway): %s", u.String())
	}
	rd, err := gobpf.NewReader(&Greetings)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	if *selftest {
		os.Exit(runSelftest(objs, rd, *target))
	}
	l, err := gobpf.AttachUprobe(objs, OnGreet, gobpf.UprobeTarget{PID: *pid})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	deadline := time.Now().Add(*duration)
	for {
		rd.SetDeadline(time.Now().Add(time.Second))
		ev, err := rd.Read()
		switch {
		case err == nil && ev.Status < 0:
			fmt.Printf("greet n=%d name unreadable (read_str status %d)\n", ev.N, ev.Status)
			fmt.Println("  " + describeStack(ev).line)
		case err == nil:
			fmt.Printf("greet n=%d name=%q\n", ev.N, bytes.TrimRight(ev.Name[:], "\x00"))
			fmt.Println("  " + describeStack(ev).line)
		case !errors.Is(err, os.ErrDeadlineExceeded):
			log.Fatal(err)
		}
		if *duration <= 0 || time.Now().After(deadline) {
			n, _ := Stats.Get(0)
			fmt.Printf("counts calls=%d\n", n)
			return
		}
	}
}

// stackView is the reading of one event's user stack.
type stackView struct {
	ips      []uint64
	frames   []bpf.StackFrame
	statuses map[bpf.StackFrameStatus]int
	nonText  int  // the number of frames outside executable file mappings (r-xp)
	symptom  bool // a sign of no frame pointer (depth 1 or a frame outside r-x)
	line     string
}

// describeStack reads the event's two stack ids and puts the depth, per-status counts and the sign on one line (a negative id is printed as a status).
func describeStack(ev Greeting) stackView {
	var v stackView
	if ev.Stack < 0 || ev.Build < 0 {
		v.line = fmt.Sprintf("user stack: status stack=%d build=%d (negative errno — not captured)", ev.Stack, ev.Build)
		return v
	}
	var err error
	if v.ips, err = Stacks.Get(uint32(ev.Stack)); err != nil {
		v.line = fmt.Sprintf("user stack: %v", err)
		return v
	}
	if v.frames, err = Builds.Get(uint32(ev.Build)); err != nil {
		v.line = fmt.Sprintf("user stack: %v", err)
		return v
	}
	depth := bpf.StackDepth(v.ips)
	v.ips = v.ips[:depth]
	v.statuses = map[bpf.StackFrameStatus]int{}
	for _, f := range v.frames {
		v.statuses[f.Status]++
	}
	maps, mapsErr := os.ReadFile(fmt.Sprintf("/proc/%d/maps", ev.Pid))
	var where []string
	for _, ip := range v.ips {
		w, text := whereIs(maps, ip)
		if !text {
			v.nonText++
		}
		where = append(where, w)
	}
	v.symptom = depth == 1 || (mapsErr == nil && v.nonText > 0)
	v.line = fmt.Sprintf("user stack: depth=%d valid=%d ip=%d frames=[%s]", depth, v.statuses[bpf.StackFrameValid], v.statuses[bpf.StackFrameIP], strings.Join(where, " "))
	switch {
	case mapsErr != nil:
		v.line += " (cannot read maps — judged by depth alone)"
	case v.symptom:
		v.line += fmt.Sprintf(" — signs of no frame pointer (depth 1 or frame %d outside r-x): rebuild the target with -fno-omit-frame-pointer if you need the callers", v.nonText)
	}
	return v
}

// whereIs returns the file name and file offset of the maps line containing the address, and whether that line is an executable file mapping (r-xp).
func whereIs(maps []byte, a uint64) (string, bool) {
	for _, l := range strings.Split(string(maps), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		r := strings.SplitN(f[0], "-", 2)
		lo, _ := strconv.ParseUint(r[0], 16, 64)
		hi, _ := strconv.ParseUint(r[1], 16, 64)
		off, _ := strconv.ParseUint(f[2], 16, 64)
		if a >= lo && a < hi {
			name := "[anon]"
			if len(f) >= 6 {
				name = filepath.Base(f[5])
			}
			return fmt.Sprintf("%s+%#x", name, a-lo+off), f[1] == "r-xp" && len(f) >= 6 && strings.HasPrefix(f[5], "/")
		}
	}
	return fmt.Sprintf("%#x", a), false
}

// greetEntry is the address of the greet entry in the process (the start of the target's offset-0 mapping + the ELF st_value — greeter is PIE).
func greetEntry(pid int, target string) (uint64, error) {
	f, err := elf.Open(target)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return 0, err
	}
	var val uint64
	for _, s := range syms {
		if s.Name == "greet" && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			val = s.Value
		}
	}
	if val == 0 {
		return 0, fmt.Errorf("%s: no FUNC symbol greet", target)
	}
	abs, _ := filepath.Abs(target)
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(maps), "\n") {
		fs := strings.Fields(l)
		if len(fs) >= 6 && fs[5] == abs && fs[2] == "00000000" {
			base, _ := strconv.ParseUint(strings.SplitN(fs[0], "-", 2)[0], 16, 64)
			return base + val, nil
		}
	}
	return 0, fmt.Errorf("no offset-0 mapping of %s in /proc/%d/maps", abs, pid)
}

func runSelftest(objs *gobpf.Objects, rd *gobpf.Reader[Greeting], target string) int {
	cmd := exec.Command(target)
	in, err := cmd.StdinPipe()
	if err != nil {
		log.Print(err)
		return 1
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		log.Print(err)
		return 1
	}
	defer func() { fmt.Fprintln(in, "q"); in.Close(); cmd.Wait() }()
	l, err := gobpf.AttachUprobe(objs, OnGreet, gobpf.UprobeTarget{PID: cmd.Process.Pid})
	if err != nil {
		log.Print(err)
		return 1
	}
	defer l.Close()
	replies := bufio.NewReader(out)
	names := []string{"gopher", "ebpf", "a-name-longer-than-thirty-one-bytes-is-truncated"}
	ok := true
	symptoms := 0
	for i, name := range names {
		fmt.Fprintln(in, name)
		if _, err := replies.ReadString('\n'); err != nil {
			log.Print(err)
			return 1
		}
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		ev, err := rd.Read()
		if err != nil {
			log.Printf("event %d: %v", i, err)
			return 1
		}
		got := string(bytes.TrimRight(ev.Name[:], "\x00"))
		want := name
		if len(want) > 31 {
			want = want[:31] // a 32-byte field — 31 characters and NUL
		}
		fmt.Printf("greet n=%d name=%q status=%d\n", ev.N, got, ev.Status)
		// Status is the length including NUL (truncated at 32 — the field size).
		if got != want || ev.N != uint32(i+1) || ev.Status != int64(len(want)+1) {
			log.Printf("event %d: n=%d name=%q status=%d, want n=%d name=%q status=%d", i, ev.N, got, ev.Status, i+1, want, len(want)+1)
			ok = false
		}
		// user stack: #0 is the greet entry, #0 of the build id stack has status 2 (greeter has no GNU build id), the element count is the IP depth
		v := describeStack(ev)
		fmt.Println("  " + v.line)
		entry, err := greetEntry(cmd.Process.Pid, target)
		switch {
		case err != nil:
			log.Printf("event %d: %v", i, err)
			ok = false
		case len(v.ips) == 0 || v.ips[0] != entry:
			log.Printf("event %d: user stack frame 0 %v, want greet at %#x", i, v.ips, entry)
			ok = false
		case len(v.frames) != len(v.ips) || v.frames[0].Status != bpf.StackFrameIP || v.frames[0].IP != entry:
			log.Printf("event %d: build id stack %+v, want %d frames with frame 0 status ip at %#x", i, v.frames, len(v.ips), entry)
			ok = false
		}
		if v.symptom {
			symptoms++
		}
	}
	n, _ := Stats.Get(0)
	ok = ok && n == uint64(len(names))
	fmt.Printf("counts calls=%d frame_pointer_symptom=%d/%d\nselftest result=%s\n", n, symptoms, len(names), map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}
