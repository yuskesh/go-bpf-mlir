package frontend

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Probe target binaries of the testdata cases. The frontend requires the path of a //gobpf:uprobe | uretprobe | usdt | uprobe_multi |
// uretprobe_multi binary to be inside the package directory, but the binaries are kept once, in internal/fixtures (no copies or symlinks
// in testdata — a Go module zip carries neither the symlinks nor needless copies). TestMain stages each case below into a temporary
// directory with the binaries its directives name and a go.mod that points at this module, and caseDir returns the staged directory.
// Diagnostics positions are relative to the package directory, so they do not change.

// caseFixtures lists, per testdata case, the fixture binaries its directives name (checked both ways by TestCaseFixturesMatchDirectives).
var caseFixtures = map[string][]string{
	"cx_uprobe_arg":            {"cfix"},
	"kr_uprobe":                {"cfix"},
	"od_in_loop":               {"cfix"},
	"od_no_userstr":            {"cfix"},
	"od_ok":                    {"cfix"},
	"od_status_discarded":      {"cfix"},
	"od_status_two":            {"cfix"},
	"od_userstr_in_literal":    {"cfix"},
	"trh_ok":                   {"cfix"},
	"trh_uret_go":              {"cgofix.bin"},
	"um_dup":                   {"umfix"},
	"um_empty":                 {"umfix"},
	"um_glob":                  {"umfix"},
	"um_no_symbol":             {"umfix"},
	"um_ok":                    {"umfix"},
	"um_str":                   {"umfix"},
	"um_wide_type":             {"umfix"},
	"uprobe_arg_str_conflict":  {"cfix"},
	"uprobe_bad_directive":     {"cfix"},
	"uprobe_go_func":           {"cgofix.bin"},
	"uprobe_no_symbol":         {"cfix"},
	"uprobe_no_userstr_field":  {"cfix"},
	"uprobe_ok":                {"cfix", "cgofix.bin"},
	"uprobe_status_discarded":  {"cfix"},
	"uprobe_status_in_literal": {"cfix"},
	"uprobe_status_int32":      {"cfix"},
	"uprobe_status_missing":    {"cfix"},
	"uprobe_status_two":        {"cfix"},
	"uprobe_str_elsewhere":     {"cfix"},
	"uprobe_str_not_char":      {"cfix"},
	"uprobe_user_side":         {"cfix"},
	"uprobe_wrong_type":        {"cfix"},
	"us_bad_target":            {"usfix"},
	"us_callee":                {"usfix"},
	"us_n13":                   {"usfix"},
	"us_nonconst":              {"usfix"},
	"us_no_point":              {"usfix"},
	"us_ok":                    {"usfix"},
	"us_ptr_uprobe":            {"cfix"},
	"ustack_ok":                {"cfix"},
	"us_too_many":              {"usfix"},
	"us_wrong_type":            {"usfix"},
	"ustr_ksys_in_uprobe":      {"cfix"},
	// Split DWARF: a separate debug file is staged as "<source>:<name>" — the name sfix's .gnu_debuglink gives (the directives do not name it).
	"usplit_ok":          {"sfix", "sfix.debug:sfix.debug"},
	"usplit_no_debug":    {"sfix"},
	"usplit_no_link":     {"sfix-nolink"},
	"usplit_other_build": {"sfix", "sfix-otherid.debug:sfix.debug"},
	"usplit_bad_crc":     {"sfix", "sfix-badcrc.debug:sfix.debug"},
	"usplit_wrong_type":  {"sfix", "sfix.debug:sfix.debug"},
	// User buffers and raw pointers (bfix — buf_write(void *ctx, const void *buf, int len), buf_argv(char **v, int n)).
	"ubuf_ok":               {"bfix"},
	"ubuf_pad_stack":        {"bfix"},
	"ubuf_pad_named":        {"bfix"},
	"ubuf_elsewhere":        {"bfix"},
	"ubuf_multi":            {"umfix"},
	"ubuf_ptr_multi":        {"umfix"},
	"ubuf_no_field":         {"bfix"},
	"ubuf_two_fields":       {"bfix"},
	"ubuf_too_big":          {"bfix"},
	"ubuf_wide_elem":        {"bfix"},
	"ubuf_no_status":        {"bfix"},
	"ubuf_len_int64":        {"bfix"},
	"ubuf_len_in_literal":   {"bfix"},
	"ubuf_status_discarded": {"bfix"},
	"ubuf_int_arg":          {"bfix"},
	"ubuf_ptr_int":          {"bfix"},
	"ubuf_char2":            {"bfix"},
	"ubuf_in_loop":          {"bfix"},
	"ubuf_twotypes":         {"bfix"},
}

// fixtureNames are the binaries in internal/fixtures.
var fixtureNames = []string{"cfix", "cgofix.bin", "umfix", "usfix", "sfix", "sfix-nolink", "bfix"}

// stagedName splits a caseFixtures entry into the file in internal/fixtures and its name in the staged case.
func stagedName(entry string) (src, dst string) {
	if s, d, ok := strings.Cut(entry, ":"); ok {
		return s, d
	}
	return entry, entry
}

// stagedCases maps a case name to its staged directory (filled by TestMain before any test runs, read only afterwards).
var stagedCases = map[string]string{}

// caseDir returns the directory to analyze for testdata case name: the staged copy for a case with fixtures, testdata/<name> otherwise.
func caseDir(name string) string {
	if d, ok := stagedCases[name]; ok {
		return d
	}
	return filepath.Join("testdata", name)
}

// stageModule is the module of the staging root's go.mod — the marker isStagedCase reads.
const stageModule = "gobpfstage"

// isStagedCase reports whether dir is a staged testdata case: its parent holds the go.mod the stage writes (the staging root may be
// inside the repository when TMPDIR is).
func isStagedCase(dir string) bool {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(dir), "go.mod"))
	return err == nil && strings.HasPrefix(string(b), "module "+stageModule+"\n")
}

func TestMain(m *testing.M) {
	root, err := stageCases()
	if err != nil {
		fmt.Fprintln(os.Stderr, "staging the testdata cases with fixtures:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

// stageCases copies every case in caseFixtures (its regular files) and its fixtures into one temporary directory with a go.mod
// that requires this module through a replace to the module root (the cases import only this module's bpf package).
func stageCases() (string, error) {
	modRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", err
	}
	gomod, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return "", err
	}
	const module = "github.com/yuskesh/go-bpf-mlir"
	if !strings.HasPrefix(string(gomod), "module "+module+"\n") {
		return "", fmt.Errorf("%s is not the go.mod of %s", filepath.Join(modRoot, "go.mod"), module)
	}
	root, err := os.MkdirTemp("", "gobpf-frontend-cases-")
	if err != nil {
		return "", err
	}
	stage := fmt.Sprintf("module %s\n\ngo 1.26.0\n\nrequire %s v0.0.0\n\nreplace %s => %s\n", stageModule, module, module, modRoot)
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(stage), 0o644); err != nil {
		return root, err
	}
	for name, fixtures := range caseFixtures {
		dst := filepath.Join(root, name)
		if err := os.Mkdir(dst, 0o755); err != nil {
			return root, err
		}
		entries, err := os.ReadDir(filepath.Join("testdata", name))
		if err != nil {
			return root, err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				return root, fmt.Errorf("testdata/%s/%s is not a regular file", name, e.Name())
			}
			if err := copyFile(filepath.Join("testdata", name, e.Name()), filepath.Join(dst, e.Name()), 0o644); err != nil {
				return root, err
			}
		}
		for _, f := range fixtures {
			src, name := stagedName(f)
			if err := copyFile(filepath.Join(modRoot, "internal", "fixtures", src), filepath.Join(dst, name), 0o755); err != nil {
				return root, err
			}
		}
		stagedCases[name] = dst
	}
	return root, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

var probeDirective = regexp.MustCompile(`(?m)^//gobpf:(?:uprobe|uretprobe|usdt|uprobe_multi|uretprobe_multi) +(\S+)`)

// Every testdata case: the fixtures its directives name = its caseFixtures entry (a named fixture not declared, or a declared fixture
// not named, fails), and no fixture binary is kept inside testdata.
func TestCaseFixturesMatchDirectives(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join("testdata", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var named []string
		for _, f := range files {
			if slices.Contains(fixtureNames, f.Name()) {
				t.Errorf("testdata/%s/%s: fixture binaries stay in internal/fixtures (the case is staged with them)", e.Name(), f.Name())
			}
			if !strings.HasSuffix(f.Name(), ".go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join("testdata", e.Name(), f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range probeDirective.FindAllStringSubmatch(string(src), -1) {
				if slices.Contains(fixtureNames, m[1]) && !slices.Contains(named, m[1]) {
					named = append(named, m[1])
				}
			}
		}
		declared, ok := caseFixtures[e.Name()]
		if !ok && len(named) == 0 {
			continue
		}
		seen[e.Name()] = true
		for _, f := range named {
			if !slices.Contains(declared, f) {
				t.Errorf("testdata/%s names fixture %s, but caseFixtures does not declare it", e.Name(), f)
			}
		}
		for _, f := range declared {
			if _, name := stagedName(f); strings.HasSuffix(name, ".debug") {
				continue // a separate debug file is named by the binary's .gnu_debuglink, not by a directive
			}
			if !slices.Contains(named, f) {
				t.Errorf("caseFixtures declares %s for testdata/%s, but no directive names it", f, e.Name())
			}
		}
	}
	for name := range caseFixtures {
		if !seen[name] {
			t.Errorf("caseFixtures has %s, which is not a testdata case", name)
		}
	}
}
