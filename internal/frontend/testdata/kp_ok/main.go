package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Field paths through embedded kernel types (a local type field of a local type by value) — the four reads:
// kfield.load (2 and 3 segments), kfield.ptr (f_path.dentry), kfield.copy (s_uuid.b) and kernel.read_str (d_name.name).

type File struct {
	_    bpf.Kernel `kernel:"file"`
	Path Path       `kernel:"f_path"`
}

type Path struct {
	_      bpf.Kernel `kernel:"path"`
	Dentry *Dentry    `kernel:"dentry"`
}

type Dentry struct {
	_    bpf.Kernel  `kernel:"dentry"`
	Name QStr        `kernel:"d_name"`
	Sb   *SuperBlock `kernel:"d_sb"`
}

type QStr struct {
	_    bpf.Kernel    `kernel:"qstr"`
	Len  uint32        `kernel:"len"`
	Name bpf.KernelStr `kernel:"name"`
}

type SuperBlock struct {
	_    bpf.Kernel `kernel:"super_block"`
	UUID UUID       `kernel:"s_uuid"`
}

type UUID struct {
	_ bpf.Kernel `kernel:"uuid_t"`
	B [16]byte   `kernel:"b"`
}

type Task struct {
	_  bpf.Kernel  `kernel:"task_struct"`
	SE SchedEntity `kernel:"se"`
}

type SchedEntity struct {
	_   bpf.Kernel `kernel:"sched_entity"`
	Avg SchedAvg   `kernel:"avg"`
}

type SchedAvg struct {
	_       bpf.Kernel `kernel:"sched_avg"`
	LoadAvg uint64     `kernel:"load_avg"`
}

type Ev struct {
	Len  uint32   `schema:"len"`
	Name [32]byte `schema:"name" gobpf:"kernelstr"`
	_    [4]byte
	St   int64 `schema:"st" gobpf:"kernelstr_status"`
}

type Info struct {
	UUID [16]byte `schema:"uuid"`
	Load uint64   `schema:"load"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

var Out = bpf.Array[uint32, Info]{MaxEntries: 1}

var Drop = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry security_file_open
func onOpen(ctx *bpf.FentryContext) {
	if f := bpf.FentryArg[File](ctx, 0); f != nil {
		if d := f.Path.Dentry; d != nil {
			if _, ok := Events.OutputKernelStr(Ev{Len: d.Name.Len}, d.Name.Name); !ok {
				Drop.AtomicAdd(0, 1)
			}
			if sb := d.Sb; sb != nil {
				if q := Out.Lookup(0); q != nil {
					q.UUID = sb.UUID.B
				}
			}
		}
	}
}

//gobpf:fentry wake_up_new_task
func onWake(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Task](ctx, 0); p != nil {
		if q := Out.Lookup(0); q != nil {
			q.Load = p.SE.Avg.LoadAvg
		}
	}
}

func main() {}
