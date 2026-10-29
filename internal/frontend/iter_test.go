package frontend

import (
	"testing"
)

// TestMlirBytes checks the MLIR spelling of SetNewValue literals (non-printable-ASCII bytes, `"` and `\` become `\XX`).
func TestMlirBytes(t *testing.T) {
	for in, want := range map[string]string{"63\n": `"63\0A"`, `a"b\c`: `"a\22b\5Cc"`, "\x00\xff": `"\00\FF"`} {
		if got := mlirBytes(in); got != want {
			t.Errorf("mlirBytes(%q) = %s, want %s", in, got, want)
		}
	}
}
