package frontend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Reason code numbers and names are append-only even during v0.x — checks docs/release/codes.tsv (the frozen table) against result.go's codeNames.
// Changing or removing an existing row's number or name fails, a code missing from the table fails until appended with the next number, and gaps or reuse fail.
func TestCodesFrozen(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "release", "codes.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	frozen := map[Code]string{}
	next := 0
	for i, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			t.Fatalf("codes.tsv line %d: %q is not <code>\\t<name>", i+1, line)
		}
		c := Code(f[0])
		if want := Code(fmt.Sprintf("GB%03d", next)); c != want {
			t.Fatalf("codes.tsv line %d: %s, want %s — the table is append-only in number order (no gaps, no reuse)", i+1, c, want)
		}
		next++
		frozen[c] = f[1]
		got, ok := codeNames[c]
		switch {
		case !ok:
			t.Errorf("%s (%s) is in the frozen table but not in result.go — a released reason code cannot be removed", c, f[1])
		case got != f[1]:
			t.Errorf("%s is %q in result.go but %q in the frozen table — a released reason code cannot be renamed", c, got, f[1])
		}
	}
	for c, name := range codeNames {
		if _, ok := frozen[c]; !ok {
			t.Errorf("%s (%s) is not in docs/release/codes.tsv — append it as the next row (GB%03d)", c, name, next)
		}
	}
	t.Logf("frozen codes: %d (GB000 to GB%03d)", len(frozen), next-1)
	// Removing a code from both the table and result.go slips past the check above — also check that the last release tag's rows prefix the current table (skipped without a tag).
	root := repoRoot(t)
	tag, err := exec.Command("git", "-C", root, "describe", "--tags", "--abbrev=0", "--match", "v*").Output()
	if err != nil {
		t.Logf("no release tag yet — the prefix check against the released table is skipped")
		return
	}
	old, err := exec.Command("git", "-C", root, "show", strings.TrimSpace(string(tag))+":docs/release/codes.tsv").Output()
	if err != nil {
		t.Fatalf("release %s has no docs/release/codes.tsv: %v", strings.TrimSpace(string(tag)), err)
	}
	// `#` comment rows are not compared (the comments were translated to English — row numbers, names, order and the release's row count are checked as strictly).
	released, now := codeRows(string(old)), codeRows(string(b))
	if len(now) < len(released) || strings.Join(now[:len(released)], "\n") != strings.Join(released, "\n") {
		t.Errorf("docs/release/codes.tsv does not start with the %d code rows of release %s — released rows cannot change or be removed", len(released), strings.TrimSpace(string(tag)))
	}
}

// codeRows returns the code rows of codes.tsv (excluding `#` comment rows and blank lines — in order).
func codeRows(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}
