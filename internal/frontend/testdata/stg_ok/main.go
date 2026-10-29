package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: declarations of the four kinds, Get with and without create, Delete, integer and record values, tp_btf and fentry owners.

type Task struct {
	_   bpf.Kernel `kernel:"task_struct"`
	Pid int32      `kernel:"pid"`
}

type Sock struct {
	_    bpf.Kernel `kernel:"sock"`
	Mark uint32     `kernel:"sk_mark"`
}

type Cgroup struct {
	_     bpf.Kernel `kernel:"cgroup"`
	Level int32      `kernel:"level"`
}

type Inode struct {
	_     bpf.Kernel `kernel:"inode"`
	Flags uint32     `kernel:"i_flags"`
}

type Count struct {
	N uint64 `schema:"n"`
}

var (
	Tasks  = bpf.TaskStorage[Count]{}
	Socks  = bpf.SKStorage[uint64]{}
	Cgrps  = bpf.CgrpStorage[Count]{}
	Inodes = bpf.InodeStorage[Count]{}
	Out    = bpf.Array[uint32, uint64]{MaxEntries: 4}
)

//gobpf:tp_btf sched_process_fork
func fork(ctx *bpf.TPBTFContext) {
	_ = bpf.TPArg[Task](ctx, 0)
	child := bpf.TPArg[Task](ctx, 1)
	if v := Tasks.Get(child, bpf.Create); v != nil {
		bpf.AtomicAdd(&v.N, 1)
	}
}

//gobpf:fentry tcp_sendmsg
func send(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Sock](ctx, 0); p != nil {
		if v := Socks.Get(p, bpf.NoCreate); v != nil {
			Out.Update(0, *v)
		}
		st := Socks.Delete(p)
		Out.Update(1, uint64(st))
	}
}

//gobpf:tp_btf cgroup_mkdir
func mkdir(ctx *bpf.TPBTFContext) {
	cg := bpf.TPArg[Cgroup](ctx, 0)
	if v := Cgrps.Get(cg, bpf.Create); v != nil {
		bpf.AtomicAdd(&v.N, 1)
	} else {
		Out.AtomicAdd(2, 1)
	}
}

//gobpf:fentry security_inode_permission
func perm(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Inode](ctx, 0); p != nil {
		if v := Inodes.Get(p, bpf.Create); v != nil {
			bpf.AtomicAdd(&v.N, 1)
		}
	}
}

func main() {}
