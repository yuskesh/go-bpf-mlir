package bpf

import (
	"testing"
	"unsafe"
)

// UserStr has the size and alignment of a pointer: a tracepoint event struct with a UserStr field has the C layout (the frontend takes the offsets from Go's layout).
// The array lengths make a size change a compile error, not only a test failure.
var (
	_ [unsafe.Sizeof(UserStr{}) - 8]struct{}
	_ [8 - unsafe.Sizeof(UserStr{})]struct{}
	_ [unsafe.Alignof(UserStr{}) - 8]struct{}
	_ [8 - unsafe.Alignof(UserStr{})]struct{}
	_ [unsafe.Sizeof(UserStrArray{}) - 8]struct{}
	_ [8 - unsafe.Sizeof(UserStrArray{})]struct{}
	_ [unsafe.Alignof(UserStrArray{}) - 8]struct{}
	_ [8 - unsafe.Alignof(UserStrArray{})]struct{}
)

func TestUserStrLayout(t *testing.T) {
	if s, a := unsafe.Sizeof(UserStr{}), unsafe.Alignof(UserStr{}); s != 8 || a != 8 {
		t.Fatalf("bpf.UserStr is %d bytes with %d-byte alignment, want 8 and 8 (a pointer)", s, a)
	}
	if s, a := unsafe.Sizeof(UserStrArray{}), unsafe.Alignof(UserStrArray{}); s != 8 || a != 8 {
		t.Fatalf("bpf.UserStrArray is %d bytes with %d-byte alignment, want 8 and 8 (a pointer)", s, a)
	}
}
