package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Every form of the local kernel type extension — 8 / 16 / 64 bit fields, copying comm, pointer walks (with else), TPArgInt,
// checking a TPArg that may be NULL, fentry's FentryArg.

type Task struct {
	_          bpf.Kernel `kernel:"task_struct"`
	Pid        int32      `kernel:"pid"`
	Tgid       int32      `kernel:"tgid"`
	Start      uint64     `kernel:"start_time"`
	Migration  uint16     `kernel:"migration_disabled"`
	Holdout    uint8      `kernel:"rcu_tasks_holdout"`
	Comm       [16]byte   `kernel:"comm"`
	RealParent *Task      `kernel:"real_parent"`
	MM         *MM        `kernel:"mm"`
}

type MM struct {
	_       bpf.Kernel `kernel:"mm_struct"`
	TotalVM uint64     `kernel:"total_vm"`
}

type Ev struct {
	Comm   [16]byte `schema:"comm"`
	Start  uint64   `schema:"start"`
	VM     uint64   `schema:"vm"`
	PTgid  int32    `schema:"ptgid"`
	Mig    uint16   `schema:"mig"`
	Hold   uint8    `schema:"hold"`
	NoMM   uint8    `schema:"nomm"`
	State  uint32   `schema:"state"`
	Pre    uint8    `schema:"pre"`
	PiSeen uint8    `schema:"piseen"`
	_      [2]byte
	Woken  int32 `schema:"woken"`
	_      [4]byte
}

var Out = bpf.Array[uint32, Ev]{MaxEntries: 1}

//gobpf:tp_btf sched_process_fork
func onFork(ctx *bpf.TPBTFContext) {
	c := bpf.TPArg[Task](ctx, 1)
	if q := Out.Lookup(0); q != nil {
		q.Comm = c.Comm
		q.Start = c.Start
		q.Mig = c.Migration
		q.Hold = c.Holdout
		if rp := c.RealParent; rp != nil {
			q.PTgid = rp.Tgid
		}
		if m := c.MM; m != nil {
			q.VM = m.TotalVM
		} else {
			q.NoMM = 1
		}
	}
}

//gobpf:tp_btf sched_switch
func onSwitch(ctx *bpf.TPBTFContext) {
	pre := bpf.TPArgInt[uint8](ctx, 0)
	state := bpf.TPArgInt[uint32](ctx, 3)
	if q := Out.Lookup(0); q != nil {
		q.Pre = pre
		q.State = state
	}
}

//gobpf:tp_btf sched_pi_setprio
func onPi(ctx *bpf.TPBTFContext) {
	if pi := bpf.TPArg[Task](ctx, 1); pi != nil {
		if q := Out.Lookup(0); q != nil {
			q.PiSeen = uint8(pi.Pid & 1)
		}
	}
}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		if q := Out.Lookup(0); q != nil {
			q.Woken = p.Pid
		}
	}
}

func main() {}
