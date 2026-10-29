package gobpf

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// Reader is the user-space reader of a ring buffer (bpf.RingBuf[V]). It turns event bytes into V with the generated gobpf_V's Decode.
// It wraps cilium's ringbuf.Reader. Objects.Close also closes open Readers.
type Reader[V any] struct {
	rb     *bpf.RingBuf[V]
	symbol string
	r      *ringbuf.Reader
	rec    Record
}

// ErrReaderClosed is returned by a Read after Close (the Reader or the Objects was closed).
var ErrReaderClosed = errors.New("gobpf: the ring buffer reader is closed")

var (
	readersMu sync.Mutex
	readers   = map[closer]bool{}
)

type closer interface{ Close() error }

// NewReader creates a reader for a loaded ring buffer. Before load, after Close, or when the generated table has no record for V, it is a named error.
func NewReader[V any](rb *bpf.RingBuf[V]) (*Reader[V], error) {
	m, err := binding.Map(rb, "gobpf.NewReader")
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
		return nil, fmt.Errorf("gobpf.NewReader: ring buffer %s: the generated binding has no record for %s (run go generate again)", binding.Symbol(rb), want)
	}
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("gobpf.NewReader: ring buffer %s: %w", binding.Symbol(rb), err)
	}
	rd := &Reader[V]{rb: rb, symbol: binding.Symbol(rb), r: r, rec: *rec}
	readersMu.Lock()
	readers[rd] = true
	readersMu.Unlock()
	return rd, nil
}

// Read waits for and reads the next event (os.ErrDeadlineExceeded at the SetDeadline deadline). After Close it returns ErrReaderClosed.
func (r *Reader[V]) Read() (V, error) {
	var zero V
	raw, err := r.r.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return zero, fmt.Errorf("ring buffer %s: %w", r.symbol, ErrReaderClosed)
		}
		return zero, fmt.Errorf("ring buffer %s: %w", r.symbol, err)
	}
	d := r.rec.New()
	if err := d.Decode(raw.RawSample); err != nil {
		return zero, fmt.Errorf("ring buffer %s: %w", r.symbol, err)
	}
	return reflect.ValueOf(d).Elem().Convert(reflect.TypeFor[V]()).Interface().(V), nil
}

// SetDeadline sets the deadline for Read (the zero value means no deadline).
func (r *Reader[V]) SetDeadline(t time.Time) { r.r.SetDeadline(t) }

// Close closes the reader (a second call does nothing).
func (r *Reader[V]) Close() error {
	readersMu.Lock()
	delete(readers, r)
	readersMu.Unlock()
	err := r.r.Close()
	if errors.Is(err, ringbuf.ErrClosed) {
		return nil
	}
	return err
}

// closeReaders closes every open Reader (Objects.Close — before closing the maps).
func closeReaders() {
	readersMu.Lock()
	rs := make([]closer, 0, len(readers))
	for r := range readers {
		rs = append(rs, r)
	}
	readersMu.Unlock()
	for _, r := range rs {
		r.Close()
	}
}
