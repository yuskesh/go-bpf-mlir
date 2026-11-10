# Tutorial — the eBPF side and the user-space side in one Go program

go-bpf-mlir turns functions written in a restricted subset of Go into eBPF programs and builds them, together with the user-space side, into **one Go binary**.
This document starts from a new Go module outside this repository and goes through a first program, running without root, reading diagnostics, sending events, and window helpers for tcx and packets.

- The blocks of this document are **extracted from the document, run, and their output checked** as part of the project's verification (so the document does not rot). Only the blocks marked `not run by the check` are not checked
- Everything you can write: the [reference](reference/notes.md) (API, program kinds, reason codes and fixes, supported scope)

## 0. Get go-bpf-mlir

Requirements: Linux x86_64, Go 1.26 or later, and an `ebpf-compile` built from the bpf-mlir v1.21.0 source release (LLVM / MLIR 23.1.1 — follow the build instructions of that release).
`go generate` uses the `ebpf-compile` named by `EBPF_COMPILE` and checks its version against the bpf-mlir version that this go-bpf-mlir version pairs with ([release.md](release.md)).

```sh manual
export EBPF_COMPILE=/path/to/bpf-mlir/build/bin/ebpf-compile   # built from the bpf-mlir v1.21.0 source release
```

Create your own module and make the generator `gobpf` a tool of the module:

```sh manual
go mod init example.com/myprog
go get github.com/yuskesh/go-bpf-mlir@v0.19.0
go get -tool github.com/yuskesh/go-bpf-mlir/cmd/gobpf@v0.19.0
```

(These two blocks are not run by the check — the check runs the rest of this document against the go-bpf-mlir source tree it verifies.)

- go-bpf-mlir uses the upstream `github.com/cilium/ebpf` — no `replace` line is needed. Program kinds that need cilium/ebpf support which upstream does not have yet stop with a named error (see [reference/scope.md](reference/scope.md))

## 1. A first program — count packets with XDP

What the eBPF side and the user-space side **share (maps) is declared once in the Go source**. An eBPF-side function is a plain Go function that takes types from the `bpf` package:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Counts is the map shared by the eBPF side and the user-space side: [0] is the number of packets seen.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Count is the eBPF side (an XDP program). It counts each packet and passes it.
func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	return bpf.XDPPass
}
```

The user-space side is plain Go. `gobpf.Load` loads the embedded ELF (after checking the kernel's capabilities and the map layouts), and `Counts.Get` reads the same map.
`-selftest N` runs the program N times through the kernel's test run (BPF_PROG_TEST_RUN) without attaching it:

```go file=main.go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

func main() {
	selftest := flag.Int("selftest", 0, "test run N times without attaching")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs, _, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	prog, err := objs.Program(Count)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < *selftest; i++ {
		if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			log.Fatalf("test run: %v", err)
		}
	}
	n, err := Counts.Get(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("count=%d\n", n)
}
```

Generate, build, and run as root:

```sh run
go mod tidy
go generate ./...
go build -o myprog .
sudo ./myprog -selftest 3
```

```text expect
count=3
```

`go generate` writes `gobpf.mlir`, `gobpf.schema.json`, `gobpf.bpf.o` (a BPF ELF with BTF) and `gobpf_gen.go` (the ELF embedding and the typed bindings). The same source gives byte-identical outputs.

## 2. Run without root

The minimum capabilities to load an XDP program are **CAP_BPF and CAP_NET_ADMIN** (the set for each program kind is in [docs/nonroot.md](nonroot.md)). There are two ways to grant them.

**(a) Put the capabilities on the executable (setcap)** — the file then runs as an ordinary user:

```sh run
sudo setcap cap_bpf,cap_net_admin=ep ./myprog
/usr/sbin/getcap ./myprog
./myprog -selftest 2
```

```text expect
cap_net_admin,cap_bpf=ep
count=2
```

(`getcap` prints capabilities in numeric order, not in the order they were set.)

- `setcap` / `getcap` live in `/usr/sbin` (often not on an ordinary user's PATH)
- The capabilities are **attached to the executable file** — rebuilding after a source change makes a new file without them. **Run setcap again after every build** (if the content does not change, `go build` may leave the file alone and the capabilities may survive — do not rely on it)
- `setcap` older than libcap 2.43 does not know `cap_bpf` by name — use (b) or root then
- **setcap capabilities have no effect on an executable on a nosuid file system** (the kernel ignores file capabilities at exec, although `setcap` / `getcap` succeed). On many distributions `/tmp` is a nosuid tmpfs — a module under `/tmp` stops with `RemoveMemlock: failed to set memlock rlimit: operation not permitted` (in a program that does not touch the rlimit, the hint on the gobpf.Load error names the nosuid mount). Put the module somewhere without nosuid (`findmnt -no OPTIONS -T .` shows no `nosuid`), or use setpriv as in (b)

**(b) Grant the capabilities only at start (setpriv)** — the executable holds no capabilities. File capabilities drop the ambient capabilities at exec, so remove them first:

```sh run
sudo setcap -r ./myprog
sudo setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups \
	--inh-caps=-all,+bpf,+net_admin --ambient-caps=-all,+bpf,+net_admin --bounding-set=-all,+bpf,+net_admin \
	./myprog -selftest 2
```

```text expect
count=2
```

With too few capabilities, `gobpf.Load` stops at the check before loading the program and names the capabilities it needs (here without CAP_NET_ADMIN):

```sh run-fail
sudo setcap cap_bpf=ep ./myprog
./myprog -selftest 1
```

```text expect
a non-root loader needs CAP_BPF and CAP_NET_ADMIN
```

```sh run
sudo setcap -r ./myprog
```

## 3. Read the diagnostics

go-bpf-mlir **stops at shapes outside the Go subset with a positioned error** (it never silently compiles something else). An error has the form `<file>:<line>:<column>: <reason code> <name> <verdict>: <message>`, and the message says how to fix it.
The reason codes and their fixes are listed in [reference/codes.md](reference/codes.md). Here are the common ones, each written wrong on purpose (generate stops, and the fixed form passes).

**GB005 — reading a Lookup result without a nil check.** `Lookup` can return nil when the key is absent (Go semantics). The only checked shape is `if p := M.Lookup(k); p != nil { … }`:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Limit is the limit written by the user-space side (0 means do not count).
var Limit = bpf.Array[uint32, uint64]{MaxEntries: 1}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	lim := Limit.Lookup(0)
	if *lim > 0 {
		Counts.AtomicAdd(0, 1)
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB005 NilCheckShape rejected: variable lim holds a pointer to a map value (*uint64)
is read only inside `if lim := M.Lookup(k); lim != nil { … }`
```

The fixed form (read only inside the checked branch):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Limit is the limit written by the user-space side (0 means do not count).
var Limit = bpf.Array[uint32, uint64]{MaxEntries: 1}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if lim := Limit.Lookup(0); lim != nil {
		if *lim > 0 {
			Counts.AtomicAdd(0, 1)
		}
	}
	return bpf.XDPPass
}
```

```sh run
go generate ./...
```

**GB028 — reading a shared map value and writing it back.** An Array value is shared by every CPU — `*p += 1` loses counts when two CPUs run at the same time. Use an atomic add or a per-CPU map:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(0); p != nil {
		*p += 1
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB028 NonAtomicRMW rejected
use bpf.AtomicAdd / M.AtomicAdd, a per-CPU map, or bpf.WithLock
```

(The fixed form is `Counts.AtomicAdd(0, 1)` from section 1.)

**GB014 — reading outside the packet window.** Check n bytes of the packet with `if w, ok := ctx.Check(off, n); ok { … }` before reading, and index with constants inside the checked range:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		if w.U8(23) == 6 { // IPv4 protocol (offset 23) — outside the 14-byte window
			Counts.AtomicAdd(0, 1)
		}
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB014 WindowIndex rejected: w.U8(23) reads bytes [23, 23+1) outside the checked window of 14 bytes
check at least 24 bytes first (ctx.Check(off, 24))
```

(The fixed form is `ctx.Check(0, 24)` — when the packet is shorter than 24 bytes, `ok` is false and the branch is not entered.)

**GB020 — a map key not proven in range (a notice, not a stop).** Updating an Array outside its range does nothing (the count is silently lost), so the frontend reports places where it cannot prove the key is below `MaxEntries` — generation does not stop (Conditional). Prove it with a mask or a clamp:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// ByLast counts packets by the low 3 bits of their last byte (keys 0 to 7).
var ByLast = bpf.Array[uint32, uint64]{MaxEntries: 8}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	if w, ok := ctx.Check(0, 14); ok {
		ByLast.AtomicAdd(uint32(w.U8(13)), 1)
	}
	return bpf.XDPPass
}
```

```sh run
go generate ./...
```

```text expect
GB020 ArrayKeyUnproven conditional: the key of map ByLast is not proven < MaxEntries (8)
clamp it (`if k >= 8 { k = 7 }`) or mask it (`k & …`) to prove it
```

The fixed form (`& 7` proves the key is below 8 — the notice goes away):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// ByLast counts packets by the low 3 bits of their last byte (keys 0 to 7).
var ByLast = bpf.Array[uint32, uint64]{MaxEntries: 8}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	if w, ok := ctx.Check(0, 14); ok {
		ByLast.AtomicAdd(uint32(w.U8(13))&7, 1)
	}
	return bpf.XDPPass
}
```

```sh run
go generate ./... 2>&1 | grep -c GB020 || true
go build -o myprog . && sudo ./myprog -selftest 4
```

```text expect
0
count=4
```

## 4. Send events to user space — ring buffer

The event type (a Go struct — a **record**) is a shared declaration too. Fields are fixed-width integers and arrays of them, and padding is explicit as `_ [N]byte`. `Output` returns a bool saying whether the reservation succeeded — **a statement that discards it is GB017** (count dropped events, or say you discard it with `_ =`):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Counts: [0] packets seen, [1] events not sent because the ring buffer was full.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Event is the event sent to user space (4 bytes).
type Event struct {
	EtherType uint16 `schema:"ether_type"`
	First     uint8  `schema:"first"`
	_         [1]byte
}

// Events is the ring buffer (size in bytes — a power of 2 and a multiple of 4096).
var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	if w, ok := ctx.Check(0, 14); ok {
		Events.Output(Event{EtherType: w.BE16(12), First: w.U8(0)})
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB017 StatusIgnored rejected: the result of Events.Output (whether the event was submitted) is discarded
use it (`if !Events.Output(…) { … }`), pass bpf.CountDropsIn(<map>, <key>), or discard it explicitly
```

The fixed form (count the events that were not sent):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Counts: [0] packets seen, [1] events not sent because the ring buffer was full.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Event is the event sent to user space (4 bytes).
type Event struct {
	EtherType uint16 `schema:"ether_type"`
	First     uint8  `schema:"first"`
	_         [1]byte
}

// Events is the ring buffer (size in bytes — a power of 2 and a multiple of 4096).
var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, 1)
	if w, ok := ctx.Check(0, 14); ok {
		if !Events.Output(Event{EtherType: w.BE16(12), First: w.U8(0)}) {
			Counts.AtomicAdd(1, 1)
		}
	}
	return bpf.XDPPass
}
```

The user-space side reads events as Go values (`Event`) with `gobpf.NewReader(&Events)`:

```go file=main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

func main() {
	selftest := flag.Int("selftest", 0, "test run N times without attaching")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs, _, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	rd, err := gobpf.NewReader(&Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()
	prog, err := objs.Program(Count)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < *selftest; i++ {
		frame := make([]byte, 64)
		frame[0] = byte(0xa0 + i)
		frame[12], frame[13] = 0x08, 0x00 // IPv4
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			log.Fatalf("test run: %v", err)
		}
	}
	for i := 0; i < *selftest; i++ {
		rd.SetDeadline(time.Now().Add(time.Second))
		ev, err := rd.Read()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("event ether_type=%#04x first=%#02x\n", ev.EtherType, ev.First)
	}
	n, _ := Counts.Get(0)
	lost, _ := Counts.Get(1)
	fmt.Printf("count=%d lost=%d\n", n, lost)
}
```

```sh run
go generate ./...
go build -o myprog . && sudo ./myprog -selftest 2
```

```text expect
event ether_type=0x0800 first=0xa0
event ether_type=0x0800 first=0xa1
count=2 lost=0
```

The ring buffer size also bounds the event size — a declaration whose event cannot fit in the ring even once stops with GB009 (the kernel cannot take the 8-byte header plus a record that exactly fills the ring either, so an event can be at most `MaxEntries - 16` bytes — "Large ring buffer events and the reservation limit" in the [notes](reference/notes.md)).

## 5. tcx and packet window helpers

When XDP and tcx (traffic control ingress / egress) programs read a packet the same way, write the read once in a **helper that takes a window**. `bpf.Window` is the same type from `ctx.Check` in XDP and in tcx, and the helper takes a window its caller has checked (the length is the same for every caller — the helper has no ctx, so `Check` is done in the caller):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Counts: [0] XDP IPv4, [1] XDP other, [2] tcx ingress IPv4, [3] tcx ingress other.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 4}

// kind is 0 for IPv4 and 1 otherwise (a helper that takes a window — called from both XDP and tcx).
func kind(w bpf.Window) uint32 {
	k := uint32(1)
	if w.BE16(12) == 0x0800 {
		k = 0
	}
	return k
}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(1)
	if w, ok := ctx.Check(0, 14); ok {
		k = kind(w)
	}
	if k >= 2 {
		k = 1 // the frontend does not know the range of the helper's result — a clamp to prove the key (GB020)
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func CountTC(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := uint32(1)
	if w, ok := ctx.Check(0, 14); ok {
		k = kind(w)
	}
	if k >= 2 {
		k = 1
	}
	Counts.AtomicAdd(2+k, 1)
	return bpf.TCPass
}
```

```go file=main.go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

func main() {
	selftest := flag.Bool("selftest", false, "test run an IPv4 and an ARP frame through both programs without attaching")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs, _, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	if *selftest {
		// Pass program functions directly to Objects.Program and Attach… (putting them in a slice or a variable is GB004).
		px, err := objs.Program(Count)
		if err != nil {
			log.Fatal(err)
		}
		pt, err := objs.Program(CountTC)
		if err != nil {
			log.Fatal(err)
		}
		for _, prog := range []*ebpf.Program{px, pt} {
			for _, et := range [][2]byte{{0x08, 0x00}, {0x08, 0x06}} { // IPv4, ARP
				frame := make([]byte, 64) // a tcx test run needs the frame up to the IPv4 header (34 bytes or more)
				frame[12], frame[13] = et[0], et[1]
				if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
					log.Fatalf("test run: %v", err)
				}
			}
		}
	}
	var c [4]uint64
	for i := range c {
		c[i], _ = Counts.Get(uint32(i))
	}
	fmt.Printf("xdp ipv4=%d other=%d / tc-ingress ipv4=%d other=%d\n", c[0], c[1], c[2], c[3])
}
```

```sh run
go generate ./...
grep -c 'ebpf.call @kind' gobpf.mlir
go build -o myprog . && sudo ./myprog -selftest
```

```text expect
2
xdp ipv4=1 other=1 / tc-ingress ipv4=1 other=1
```

(`gobpf.mlir` has two `ebpf.call @kind` — the helper is one static BPF function called from two programs.)

To attach to a real interface, use `gobpf.AttachXDP(objs, Count, ifindex)` and `gobpf.AttachTCX(objs, CountTC, ifindex)` (the direction — ingress / egress — follows from the context type). The next fragment is **not run by the check** (it needs an interface; the project verifies attaching on a veth pair separately):

```go
ifi, err := net.InterfaceByName("eth0")
if err != nil {
	log.Fatal(err)
}
lx, err := gobpf.AttachXDP(objs, Count, ifi.Index)
if err != nil {
	log.Fatal(err)
}
defer lx.Close()
lt, err := gobpf.AttachTCX(objs, CountTC, ifi.Index)
if err != nil {
	log.Fatal(err)
}
defer lt.Close()
```

## 6. Two maps at once — borrows, and helpers that take a window and a borrow

Inside the checked branch of a Lookup, **you can Lookup one more, different map** (at most two at the same time). A helper that takes a window **can also take one pointer to a map value** (the helper only reads through it). Classify packets with a rule table (Rules) and write the result counts (Stats):

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Rule is a rule written by the user-space side: an IPv4 protocol number and the class it gets.
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

// Stat is the counted result: packets that matched the rule, and the class of the last packet (0 when it did not match).
type Stat struct {
	Hits uint64 `schema:"hits"`
	Last uint64 `schema:"last"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 1}
var Stats = bpf.Array[uint32, Stat]{MaxEntries: 2}

// classify is a helper that takes a window (the IPv4 protocol is at offset 23) and a rule pointer — the caller checked the window, and p is the caller's checked borrow.
func classify(w bpf.Window, p *Rule) uint32 {
	c := uint32(0)
	if uint32(w.U8(23)) == p.Proto {
		c = p.Class
	}
	return c
}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil { // first borrow
			if s := Stats.Lookup(0); s != nil { // second borrow (a different map)
				c := classify(w, p)
				if c != 0 {
					bpf.AtomicAdd(&s.Hits, 1)
				}
				s.Last = uint64(c)
			}
		}
	}
	return bpf.XDPPass
}
```

```go file=main.go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

func main() {
	selftest := flag.Bool("selftest", false, "test run a TCP and a UDP frame without attaching")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs, _, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	if err := Rules.Put(0, Rule{Proto: 17, Class: 7}); err != nil { // UDP (17) gets class 7
		log.Fatal(err)
	}
	if *selftest {
		prog, err := objs.Program(Count)
		if err != nil {
			log.Fatal(err)
		}
		for _, proto := range []byte{6, 17} { // TCP, then UDP
			frame := make([]byte, 64)
			frame[12], frame[13] = 0x08, 0x00 // IPv4
			frame[23] = proto
			if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
				log.Fatalf("test run: %v", err)
			}
		}
	}
	s, err := Stats.Get(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hits=%d last=%d\n", s.Hits, s.Last)
}
```

```sh run
go generate ./...
grep -c 'ebpf.ref.check' gobpf.mlir
grep -o 'ebpf.func @classify "static" (!ebpf.pkt_window<24>, !ebpf.borrowed<!ebpf.record<"Rule", 8>>)' gobpf.mlir
go build -o myprog . && sudo ./myprog -selftest
```

```text expect
2
ebpf.func @classify "static" (!ebpf.pkt_window<24>, !ebpf.borrowed<!ebpf.record<"Rule", 8>>)
hits=1 last=7
```

(Two nested `ebpf.ref.check` — the Stats check sits inside the checked branch of the Rules borrow. The helper is one static BPF function whose arguments are a window and a borrow. TCP does not match the rule; UDP matches and gets class 7.)

**GB029 — a second borrow that may point to the same value.** When the second Lookup is on **the same map** and its key cannot be shown to differ from the first (a variable key, or the same constant key), the two pointers may point to the same value — it stops (a different map, or **a different constant** key on the same map, is accepted). Add a program that copies Last of Stats[0] into Stats[k] chosen by the packet:

```go file=extra.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Copy copies Last of Stats[0] into Stats[k] chosen by the packet.
func Copy(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		k := uint32(w.U8(23)) & 1
		if s := Stats.Lookup(0); s != nil {
			if t := Stats.Lookup(k); t != nil { // the same value as s when k is 0
				t.Last = s.Last
			}
		}
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB029 BorrowAlias rejected: Stats.Lookup(k) inside the checked branch of s may point to the same value as s (both are values of map Stats and the keys are not both constants)
copy the value you need to a local before the second Lookup
```

The fixed form (copy the needed value from the first borrow into a local, close the branch, then do the second Lookup):

```go file=extra.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Copy copies Last of Stats[0] into Stats[k] chosen by the packet.
func Copy(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		k := uint32(w.U8(23)) & 1
		last := uint64(0)
		if s := Stats.Lookup(0); s != nil {
			last = s.Last
		}
		if t := Stats.Lookup(k); t != nil {
			t.Last = last
		}
	}
	return bpf.XDPPass
}
```

```sh run
go generate ./... && echo generated
```

```text expect
generated
```

## 7. Helpers that take the context

When two programs of the same kind read a packet the same way, the read — `Check` included — can go in a **helper that takes the program context as its first argument**. Count IPv4 and IPv6 in separate programs, with the ethertype read in one helper:

```go file=bpf.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//go:generate go tool gobpf

// Counts: [0] IPv4 in ParseIPv4, [1] other in ParseIPv4, [2] IPv6 in ParseIPv6, [3] other in ParseIPv6.
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 4}

// etype is the ethertype of the frame (0 when shorter than 14 bytes) — a helper that takes the context, with the Check inside the helper.
func etype(ctx *bpf.XDPContext) uint32 {
	t := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		t = uint32(w.BE16(12))
	}
	return t
}

func ParseIPv4(ctx *bpf.XDPContext) bpf.XDPAction {
	if etype(ctx) == 0x0800 {
		Counts.AtomicAdd(0, 1)
	} else {
		Counts.AtomicAdd(1, 1)
	}
	return bpf.XDPPass
}

func ParseIPv6(ctx *bpf.XDPContext) bpf.XDPAction {
	if etype(ctx) == 0x86dd {
		Counts.AtomicAdd(2, 1)
	} else {
		Counts.AtomicAdd(3, 1)
	}
	return bpf.XDPPass
}
```

```go file=main.go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

func main() {
	selftest := flag.Bool("selftest", false, "test run an IPv4, an IPv6 and an ARP frame through both programs without attaching")
	flag.Parse()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs, _, err := gobpf.Load(livecaps.New())
	if err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()
	if *selftest {
		p4, err := objs.Program(ParseIPv4)
		if err != nil {
			log.Fatal(err)
		}
		p6, err := objs.Program(ParseIPv6)
		if err != nil {
			log.Fatal(err)
		}
		for _, prog := range []*ebpf.Program{p4, p6} {
			for _, et := range [][2]byte{{0x08, 0x00}, {0x86, 0xdd}, {0x08, 0x06}} { // IPv4, IPv6, ARP
				frame := make([]byte, 64)
				frame[12], frame[13] = et[0], et[1]
				if _, err := prog.Run(&ebpf.RunOptions{Data: frame}); err != nil {
					log.Fatalf("test run: %v", err)
				}
			}
		}
	}
	var c [4]uint64
	for i := range c {
		c[i], _ = Counts.Get(uint32(i))
	}
	fmt.Printf("ParseIPv4 ipv4=%d other=%d / ParseIPv6 ipv6=%d other=%d\n", c[0], c[1], c[2], c[3])
}
```

Remove `extra.go` from section 6 (it uses Stats) before generating:

```sh run
rm -f extra.go
go generate ./...
grep -o 'ebpf.func @etype "static" (!ebpf.ctx<"xdp">) -> i32' gobpf.mlir
grep -c 'ebpf.call @etype(%ctx)' gobpf.mlir
go build -o myprog . && sudo ./myprog -selftest
```

```text expect
ebpf.func @etype "static" (!ebpf.ctx<"xdp">) -> i32
2
ParseIPv4 ipv4=1 other=2 / ParseIPv6 ipv6=1 other=2
```

(The helper is one static BPF function that takes `!ebpf.ctx<"xdp">` as its first argument, and both programs call it with their own `%ctx`. The context type is a concrete type, so the helper can be called only from programs of one kind — a read used by both XDP and tcx belongs in a window helper as in section 5.)

**What a helper cannot do.** `ctx.AdjustHead` / `AdjustTail`, which change the packet (they invalidate every window), reads that depend on the attach point (`bpf.KprobeArg`, `bpf.UprobeArg`, `bpf.FentryArg` and so on), tail calls, redirects and `WithLock` belong in the program body only — inside a helper they stop with GB013 and others. Add a helper that strips a header:

```go file=extra.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// strip strips a 4-byte header (AdjustHead inside a helper).
func strip(ctx *bpf.XDPContext) int64 {
	return ctx.AdjustHead(4)
}

func Strip(ctx *bpf.XDPContext) bpf.XDPAction {
	if strip(ctx) == 0 {
		Counts.AtomicAdd(3, 1)
	}
	return bpf.XDPPass
}
```

```sh run-fail
go generate ./...
```

```text expect
GB013 SubprogramShape rejected: ctx.AdjustHead changes the packet (it invalidates every window), which a subprogram that takes the context cannot do
adjust in the program and pass the status as an integer if the helper needs it
```

The fixed form (AdjustHead in the program body):

```go file=extra.go
package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func Strip(ctx *bpf.XDPContext) bpf.XDPAction {
	if ctx.AdjustHead(4) == 0 {
		Counts.AtomicAdd(3, 1)
	}
	return bpf.XDPPass
}
```

```sh run
go generate ./... && echo generated
```

```text expect
generated
```

## 8. Where to read next

- The API you can write and the program kinds: [reference/api.md](reference/api.md), [reference/kinds.md](reference/kinds.md)
- Every reason code and its fix: [reference/codes.md](reference/codes.md)
- The supported scope (feature groups, evidence, unmeasured paths) and what is outside it: [reference/scope.md](reference/scope.md)
- Cross-cutting notes (differences from Go semantics, non-root, loops, helper costs, large events and more): [reference/notes.md](reference/notes.md)
- Working examples (16): [reference/examples.md](reference/examples.md) — tracing (fentry / kprobe / uprobe / tp_btf), lpm_trie, devmap, timer, spin lock and more
- Versions and compatibility: [release.md](release.md)
