//go:build linux

package kload

// Whether the target's bpf_fib_lookup accepts a
// flag mask for XDP. The answer is never taken from BTF or a declaration: a
// GPL XDP program calls fib_lookup on a zeroed 64-byte params (family
// AF_UNSPEC) with the mask, returns the helper's result in r0, and runs once
// through BPF_PROG_TEST_RUN. bpf_fib_lookup checks plen and flags before the
// family (see the bpf_fib_lookup source), so -EAFNOSUPPORT means the mask passed the flag check
// (true) and -EINVAL means it did not (false). Every other outcome — load
// failure, test_run errno, 0, a positive FIB status, another errno — is
// Unknown. The probe runs only for the canonical xdp name with the UAPI xdp ID
// and a mask a fibflags row can carry; anything else is Unknown without a
// probe. Running it needs root; this file is the implementation.

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// fibXDPProgTypeID is the UAPI BPF_PROG_TYPE_XDP (a test checks abi/uapi.tsv).
const fibXDPProgTypeID = 6

// fibParamsSize is the UAPI sizeof(struct bpf_fib_lookup) (a test checks abi/uapi.tsv).
const fibParamsSize = 64

// fibLookupHelper is BPF_FUNC_fib_lookup (a test checks abi/uapi.tsv).
const fibLookupHelper = 69

// fibProbe runs the probe for mask and returns the 32-bit test_run retval.
// Tests replace it to count calls; nil error means the program loaded and ran.
var fibProbe = runFibProbe

var (
	fibMu    sync.Mutex
	fibCache = map[string]fibResult{}
)

type fibResult struct {
	has bool
	err error
}

func (LiveCaps) HasFibLookupFlags(progType string, progTypeID int64, mask uint32) (bool, error) {
	if progType != "xdp" || progTypeID != fibXDPProgTypeID {
		return false, unknownf("no fib_lookup flag probe for program type %s/%d (only xdp/%d)", progType, progTypeID, fibXDPProgTypeID)
	}
	if !fibMaskCarried(mask) {
		return false, unknownf("fib_lookup flag mask %d is not one a fibflags row carries", mask)
	}
	key := requirements.FibLookupFlagsKey(progType, progTypeID, mask)
	fibMu.Lock()
	defer fibMu.Unlock()
	if r, ok := fibCache[key]; ok {
		return r.has, r.err
	}
	retval, err := fibProbe(mask)
	has, err := fibVerdict(retval, err)
	fibCache[key] = fibResult{has, err}
	return has, err
}

func fibMaskCarried(mask uint32) bool {
	for _, m := range requirements.FibFlagMasks {
		if m == mask {
			return true
		}
	}
	return false
}

// fibVerdict maps the probe's outcome: the low 32 bits of the helper's i64
// result, sign-extended (XDP test_run returns a u32 retval).
func fibVerdict(retval uint32, err error) (bool, error) {
	if err != nil {
		return false, unknownf("the fib_lookup probe did not run (%v)", err)
	}
	switch r := int32(retval); r {
	case -int32(unix.EAFNOSUPPORT):
		return true, nil
	case -int32(unix.EINVAL):
		return false, nil
	default:
		return false, unknownf("the fib_lookup probe returned %d (only -EAFNOSUPPORT or -EINVAL decide)", r)
	}
}

// fibProbeInstructions: zero 64 bytes at r10-64, fib_lookup(ctx, r10-64, 64, mask), return r0.
func fibProbeInstructions(mask uint32) asm.Instructions {
	// cilium's StoreImm has no DWord form (it returns InvalidOpCode); store r0 = 0.
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R0, 0)}
	for off := -fibParamsSize; off < 0; off += 8 {
		ins = append(ins, asm.StoreMem(asm.R10, int16(off), asm.R0, asm.DWord))
	}
	return append(ins,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -fibParamsSize),
		asm.Mov.Imm(asm.R3, fibParamsSize),
		asm.Mov.Imm(asm.R4, int32(mask)),
		asm.FnFibLookup.Call(),
		asm.Return(),
	)
}

func runFibProbe(mask uint32) (uint32, error) {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ebpf_fib_probe", Type: ebpf.XDP, Instructions: fibProbeInstructions(mask), License: "GPL"})
	if err != nil {
		return 0, fmt.Errorf("load: %w", err)
	}
	defer p.Close()
	ret, err := p.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
	if err != nil {
		return 0, fmt.Errorf("test_run: %w", err)
	}
	return ret, nil
}
