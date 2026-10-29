package frontend

import (
	"fmt"
	"sort"
	"strings"
)

// verify-bpf-world (a bpf-mlir research finding).
//
// The set of ops the frontend may emit is kept in **one place**. Both the frontend exit (after Analyze's emit) and the tests
// check that every op of the generated .mlir is in this set. The set's ebpf ops must be a subset of the "① input ops" of bpf-mlir's docs/reference/ebpf_ops.md (a test — a bpf-mlir version
// bump shows the difference — a review point). **Ops that are never emitted are not listed** (scf is not emitted, so it is not listed — a review point).
// Widen the set in the same commit as the lowering that emits the op (emitting it shows up as an allowedOps change).

var allowedOps = map[string]bool{
	// ebpf dialect (① — what the core lowering emits)
	// kprobe.arg; verdict.if is the conditional verdict; kfield.ptr, kfield.copy and kptr.check read kernel structs
	"ebpf.program":            true,
	"ebpf.func":               true,
	"ebpf.call":               true,
	"ebpf.return":             true,
	"ebpf.verdict":            true,
	"ebpf.verdict.if":         true,
	"ebpf.kprobe.arg":         true,
	"ebpf.redirect_map":       true,
	"ebpf.uprobe.arg":         true,
	"ebpf.usdt.arg":           true,
	"ebpf.sk.redirect":        true,
	"ebpf.msg.redirect":       true,
	"ebpf.sock.map_update":    true,
	"ebpf.user.read_str":      true,
	"ebpf.kernel.read_str":    true,
	"ebpf.sock.map_lookup":    true, // the Assign set
	"ebpf.sock.ref_check":     true,
	"ebpf.sk.assign":          true,
	"ebpf.sock.release":       true,
	"ebpf.sys.bpf":            true,
	"ebpf.sys.close":          true,
	"ebpf.stack.kernel_id":    true,
	"ebpf.stack.user_id":      true, // user stack (IP and build id)
	"ebpf.perf.output":        true,
	"ebpf.ctx.arg":            true,
	"ebpf.kfield.load":        true,
	"ebpf.kfield.ptr":         true,
	"ebpf.kfield.copy":        true,
	"ebpf.kptr.check":         true,
	"ebpf.spin.region":        true,
	"ebpf.timer.init":         true,
	"ebpf.timer.set_callback": true,
	"ebpf.timer.start":        true,
	"ebpf.timer.callback":     true,
	"ebpf.timer.done":         true,
	"ebpf.map.lookup":         true,
	"ebpf.map.update":         true,
	"ebpf.map.atomic_add":     true,
	"ebpf.ref.check":          true,
	"ebpf.ref.load":           true,
	"ebpf.yield":              true,
	"ebpf.if":                 true,
	"ebpf.if.yield":           true,
	"ebpf.packet.check":       true,
	"ebpf.packet.window_load": true,
	"ebpf.byteorder.from_be":  true,
	// record
	"ebpf.record.make":     true,
	"ebpf.ref.field.load":  true,
	"ebpf.ref.field.store": true,
	// ring buffer
	"ebpf.ringbuf.reserve":      true,
	"ebpf.ringbuf.if_reserved":  true,
	"ebpf.ringbuf.store_record": true,
	"ebpf.ringbuf.submit":       true,
	// OutputStr's status field
	"ebpf.ringbuf.store_field": true,
	// OutputStrOrDiscard's read-failure arm (bpf-mlir v1.3.0's conditional discard)
	"ebpf.ringbuf.discard": true,
	// status-returning hash-family operations
	// ref.atomic_add is AddOrInit
	"ebpf.map.try_update": true,
	"ebpf.map.try_delete": true,
	"ebpf.ref.atomic_add": true,
	// bpf.AtomicAdd (bpf-mlir v0.5.0)
	"ebpf.ref.field.atomic_add": true,
	// fentry task information
	"ebpf.task.pid_tgid": true,
	"ebpf.ktime.ns":      true,
	"ebpf.task.comm":     true,
	// fexit return value
	"ebpf.ctx.retval": true,
	// tracepoint fields, raw_tp args, kretprobe / uretprobe return values
	"ebpf.tp.field":     true,
	"ebpf.ctx.field":    true,
	"ebpf.probe.retval": true,
	// writes to socket and cgroup context fields
	"ebpf.ctx.field.store": true,
	// raw_tp_writable's writable buffer
	"ebpf.tp.buffer.load":  true,
	"ebpf.tp.buffer.store": true,
	// syscall ctx reads
	"ebpf.ctx.load": true,
	// writes to struct_ops kernel integer fields (struct_ops only)
	"ebpf.kfield.store": true,
	// arguments of the function an ext program replaces
	"ebpf.ext.arg": true,
	// cgroup_array
	"ebpf.task.under_cgroup": true,
	"ebpf.skb.under_cgroup":  true,
	// user_ringbuf drain and callback
	"ebpf.user_ringbuf.drain":    true,
	"ebpf.user_ringbuf.callback": true,
	"ebpf.user_ringbuf.done":     true,
	"ebpf.dynptr.read":           true,
	// iter output
	"ebpf.seq.write": true,
	// cgroup_sysctl value replacement
	"ebpf.sysctl.set_new_value": true,
	// sk_reuseport selection
	"ebpf.sk.select_reuseport": true,
	// flow_dissector flow_keys
	"ebpf.flow_keys.load":  true,
	"ebpf.flow_keys.store": true,
	// fsession session ops
	"ebpf.session.is_return":    true,
	"ebpf.session.cookie.load":  true,
	"ebpf.session.cookie.store": true,
	// local storage maps
	"ebpf.storage.get":    true,
	"ebpf.storage.delete": true,
	// keyless maps
	"ebpf.map.push":           true,
	"ebpf.map.pop":            true,
	"ebpf.map.peek":           true,
	"ebpf.bloom.peek":         true,
	"ebpf.map.inner":          true, // map-in-map
	"ebpf.ksyscall.arg":       true, // ksyscall
	"ebpf.probe.target_index": true, // multi probes
	// reads behind a kprobe pointer argument (bpf-mlir v1.11.0)
	"ebpf.kernel.read_scalar": true,
	// bounded loops
	"ebpf.loop":       true,
	"ebpf.loop.yield": true,
	"ebpf.break":      true,
	"ebpf.continue":   true,
	// variable indexes into record arrays
	"ebpf.ref.index":  true,
	"ebpf.elem.load":  true,
	"ebpf.elem.store": true,
	// sched_cls redirect terminators
	"ebpf.redirect": true,
	// xdp tail call terminators
	"ebpf.tail_call": true,
	// XDP packet rewrites
	"ebpf.packet.store":    true,
	"ebpf.byteorder.to_be": true,
	"ebpf.xdp.adjust_head": true,
	"ebpf.xdp.adjust_tail": true,
	// global variables
	"ebpf.global.load":       true,
	"ebpf.global.atomic_add": true,
	// arith (ebpf-compile's dialect restriction allows arith)
	"arith.constant": true,
	"arith.addi":     true,
	"arith.subi":     true,
	"arith.muli":     true,
	"arith.andi":     true,
	"arith.ori":      true,
	"arith.xori":     true,
	"arith.shli":     true,
	"arith.shrui":    true,
	"arith.shrsi":    true,
	"arith.divui":    true,
	"arith.divsi":    true,
	"arith.remui":    true,
	"arith.remsi":    true,
	"arith.cmpi":     true,
	"arith.extui":    true,
	"arith.extsi":    true,
	"arith.trunci":   true,
	// sign correction in the expansion of signed division by a non-power-of-two constant
	"arith.select": true,
}

// mlirOps returns the op names of ebpf dialect text in order of appearance (the !ebpf.… types are not ops).
func mlirOps(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case s == "", strings.HasPrefix(s, "//"), strings.HasPrefix(s, "^"), strings.HasPrefix(s, "}"):
			continue // empty lines, comments, block labels, region closes (`} else {` etc.)
		case strings.HasPrefix(s, "%"):
			i := strings.Index(s, "= ")
			if i < 0 {
				out = append(out, "<unparsed:"+s+">")
				continue
			}
			s = s[i+2:]
		}
		op := s
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			op = s[:i]
		}
		out = append(out, op)
	}
	return out
}

// verifyBPFWorld checks that every op of the generated .mlir is in allowedOps and returns the ops that are not (in order of appearance, no duplicates).
func verifyBPFWorld(text string) []string {
	seen := map[string]bool{}
	var bad []string
	for _, op := range mlirOps(text) {
		if !allowedOps[op] && !seen[op] {
			seen[op] = true
			bad = append(bad, op)
		}
	}
	return bad
}

// allowedOpNames returns allowedOps sorted by name (for tests and records).
func allowedOpNames() []string {
	var out []string
	for op := range allowedOps {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

func bpfWorldError(bad []string) string {
	return fmt.Sprintf("internal: the emitted .mlir contains op(s) outside the frontend's allowed set: %s — this is a gobpf frontend bug, please report it (verify-bpf-world)", strings.Join(bad, ", "))
}
