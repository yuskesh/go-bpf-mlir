package gobpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// The user ring buffer writer. The fork's cilium has no user-space writer — this uses the same mappings and write order as bpf-mlir v1.11.0's kernel/cmd/ringext/main.go
// (the runner's user side — copied, not imported, because it is package main):
//
//   - Mappings: the consumer_pos page at offset 0 is PROT_READ only (the kernel's ringbuf_map_mmap_user refuses a writable mapping with EPERM); at offset PAGE_SIZE,
//     the producer_pos page and data, PAGE_SIZE + 2 × max_entries, PROT_READ|PROT_WRITE (data is mapped twice — contiguous even across the end)
//   - Writes: total = round_up(len + 8, 8); full if producer + total − consumer > size (the same formula as libbpf's user_ring_buffer__reserve).
//     Copy the body → zero the header pad → atomic store of the header len → advance producer_pos with an atomic store (this order — the kernel's
//     __bpf_user_ringbuf_peek reads producer_pos and the header with smp_load_acquire). No BUSY / DISCARD bits (a sample is shown only after it is written)

const userRingHdrSz = 8

// ErrUserRingFull means the ring has no space at Write (nothing can be written until the eBPF side's Drain advances the consumer).
var ErrUserRingFull = errors.New("gobpf: the user ring buffer is full")

// UserRingWriter is the user-space writer of a user ring buffer (bpf.UserRingBuf[V]). One writer per ring (concurrent Writes are serialized by a Mutex).
type UserRingWriter[V any] struct {
	mu     sync.Mutex
	symbol string
	cons   []byte
	prod   []byte
	size   uint64
	recSz  uintptr
	closed bool
}

// NewUserRingWriter creates a writer for a loaded user ring buffer (mmap). Before load, after Close, or when the generated table has no record for V, it is a named error.
func NewUserRingWriter[V any](rb *bpf.UserRingBuf[V]) (*UserRingWriter[V], error) {
	m, err := binding.Map(rb, "gobpf.NewUserRingWriter")
	if err != nil {
		return nil, err
	}
	o, err := current()
	if err != nil {
		return nil, err
	}
	want := reflect.TypeFor[V]()
	var rec *Record
	for i := range o.Records {
		if o.Records[i].Type == want {
			rec = &o.Records[i]
		}
	}
	if rec == nil {
		return nil, fmt.Errorf("gobpf.NewUserRingWriter: user ring buffer %s: the generated binding has no record for %s (run go generate again)", binding.Symbol(rb), want)
	}
	if m.Type() != ebpf.UserRingbuf {
		return nil, fmt.Errorf("gobpf.NewUserRingWriter: map %s is %v, not a user ring buffer", binding.Symbol(rb), m.Type())
	}
	page := os.Getpagesize()
	size := uint64(m.MaxEntries())
	cons, err := unix.Mmap(m.FD(), 0, page, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("gobpf.NewUserRingWriter: %s: mmap consumer_pos: %w", binding.Symbol(rb), err)
	}
	prod, err := unix.Mmap(m.FD(), int64(page), page+2*int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(cons)
		return nil, fmt.Errorf("gobpf.NewUserRingWriter: %s: mmap producer_pos and data: %w", binding.Symbol(rb), err)
	}
	return &UserRingWriter[V]{symbol: binding.Symbol(rb), cons: cons, prod: prod, size: size, recSz: rec.Size}, nil
}

// Write writes v as one sample (the record's little-endian bytes). With no space it returns ErrUserRingFull (and writes nothing).
func (w *UserRingWriter[V]) Write(v V) error {
	body, err := binary.Append(nil, binary.LittleEndian, v)
	if err != nil {
		return fmt.Errorf("user ring buffer %s: encode: %w", w.symbol, err)
	}
	if uintptr(len(body)) != w.recSz {
		return fmt.Errorf("user ring buffer %s: the record encodes to %d bytes, but its layout is %d bytes (a padded record cannot be written field by field)", w.symbol, len(body), w.recSz)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("user ring buffer %s: the writer is closed", w.symbol)
	}
	page := uint64(os.Getpagesize())
	total := (uint64(len(body)) + userRingHdrSz + 7) / 8 * 8
	cons := atomic.LoadUint64((*uint64)(unsafe.Pointer(&w.cons[0])))
	pos := atomic.LoadUint64((*uint64)(unsafe.Pointer(&w.prod[0])))
	if pos+total-cons > w.size {
		return fmt.Errorf("user ring buffer %s: %w (%d + %d bytes, consumer %d, size %d)", w.symbol, ErrUserRingFull, pos, total, cons, w.size)
	}
	data := w.prod[page:]
	off := pos & (w.size - 1)
	copy(data[off+userRingHdrSz:], body)           // data is mapped twice — a write across the end stays contiguous
	binary.LittleEndian.PutUint32(data[off+4:], 0) // the header pad
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&data[off])), uint32(len(body)))
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&w.prod[0])), pos+total)
	return nil
}

// Close unmaps the ring (later calls do nothing).
func (w *UserRingWriter[V]) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return errors.Join(unix.Munmap(w.prod), unix.Munmap(w.cons))
}
