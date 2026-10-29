// openwatch is a **kprobe** example (//gobpf:kprobe) on the entry of the kernel function do_sys_openat2: it counts opens per tgid and splits them by the first argument dirfd
// (bpf.KprobeArg[int32] — AT_FDCWD = -100 or the fd of an open directory). -pid goes into the .rodata Config (Optional — 0 means every process).
//
//	openwatch [-pid N] [-duration 5s]   # attach and print the counts per tgid
//	openwatch -selftest                 # filter on its own tgid, call openat(2) 5 times with AT_FDCWD and 3 times with a dirfd, and check the counts
//	openwatch -parse-only               # parse the embedded ELF without touching the kernel (no root needed)
//
// gobpf.Load checks the argument type (dirfd is int) and the attach point (do_sys_openat2 is in kallsyms and is not redirected to an __x64_ alias) against
// the target BTF before load, and gobpf.AttachKprobe verifies the actual attach point after attach. Non-root needs CAP_BPF + CAP_PERFMON.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

//go:generate go tool gobpf

// Target is the tgid to count (.rodata — 0 means every process).
var Target = bpf.Config[uint32]{Optional: true}

// Cwd is the number of AT_FDCWD opens per tgid, Dir the number of opens from a directory fd.
var (
	Cwd = bpf.Hash[uint32, uint64]{MaxEntries: 4096}
	Dir = bpf.Hash[uint32, uint64]{MaxEntries: 4096}
)

const atFdcwd = -100 // AT_FDCWD (include/uapi/linux/fcntl.h)

// OnOpen is the eBPF side (a kprobe program).
//
//gobpf:kprobe do_sys_openat2
func OnOpen(ctx *bpf.KprobeContext) {
	tg := uint32(bpf.CurrentPidTgid() >> 32)
	want := Target.Value()
	if want == 0 || tg == want {
		if bpf.KprobeArg[int32](ctx, 1) == atFdcwd {
			_ = Cwd.AddOrInit(tg, 1) // a failure on a full table is not counted (an example — the status is discarded)
		} else {
			_ = Dir.AddOrInit(tg, 1)
		}
	}
}

func main() {
	pid := flag.Int("pid", 0, "tgid to count (0 = all)")
	duration := flag.Duration("duration", 0, "run for this long, then exit (0 = print once and exit)")
	selftest := flag.Bool("selftest", false, "count this process's openat(2) calls and check them")
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
	l, err := gobpf.AttachKprobe(objs, OnOpen)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	if *selftest {
		os.Exit(runSelftest())
	}
	deadline := time.Now().Add(*duration)
	for {
		printCounts()
		if *duration <= 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Second)
	}
}

func printCounts() {
	counts := map[uint32][2]uint64{}
	// A map variable is used only as a receiver (GB009 — no & or copy), so the two tables are read separately.
	add := func(i int, it *bpf.Iterator[uint32, uint64]) bool {
		for it.Next() {
			c := counts[it.Key()]
			c[i] = it.Value()
			counts[it.Key()] = c
		}
		if err := it.Err(); err != nil {
			log.Printf("cannot read the counter: %v", err)
			return false
		}
		return true
	}
	if !add(0, Cwd.Iterate()) || !add(1, Dir.Iterate()) {
		return
	}
	tgids := make([]uint32, 0, len(counts))
	for tg := range counts {
		tgids = append(tgids, tg)
	}
	sort.Slice(tgids, func(i, j int) bool { return tgids[i] < tgids[j] })
	for _, tg := range tgids {
		fmt.Printf("opens tgid=%d cwd=%d dirfd=%d\n", tg, counts[tg][0], counts[tg][1])
	}
}

func runSelftest() int {
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY, 0) // this open also counts (as an AT_FDCWD open)
	if err != nil {
		log.Print(err)
		return 1
	}
	defer unix.Close(root)
	before := func() (uint64, uint64) {
		c, _ := Cwd.Get(uint32(os.Getpid()))
		d, _ := Dir.Get(uint32(os.Getpid()))
		return c, d
	}
	c0, d0 := before()
	const nCwd, nDir = 5, 3
	for i := 0; i < nCwd; i++ {
		fd, err := unix.Openat(unix.AT_FDCWD, "/dev/null", unix.O_RDONLY, 0)
		if err != nil {
			log.Print(err)
			return 1
		}
		unix.Close(fd)
	}
	for i := 0; i < nDir; i++ {
		fd, err := unix.Openat(root, "dev/null", unix.O_RDONLY, 0)
		if err != nil {
			log.Print(err)
			return 1
		}
		unix.Close(fd)
	}
	c1, d1 := before()
	printCounts()
	ok := c1-c0 == nCwd && d1-d0 == nDir
	fmt.Printf("selftest cwd=+%d/%d dirfd=+%d/%d result=%s\n", c1-c0, nCwd, d1-d0, nDir, map[bool]string{true: "ok", false: "FAIL"}[ok])
	if !ok {
		return 1
	}
	return 0
}
