// gobpf is the build entry point of go-bpf-mlir. In a package directory:
//
//	//go:generate go tool gobpf
//
// turns the package's eBPF side (functions whose first parameter is *bpf.XDPContext and the functions reachable from them) into bpf-mlir ebpf dialect
// gobpf.mlir and gobpf.schema.json, compiles them with ebpf-compile into gobpf.bpf.o, and writes gobpf_gen.go, which go:embeds it and registers it
// with the runtime. Anything outside the subset stops with a position and a reason code, and nothing is written.
//
//	gobpf [-dir DIR] [-emit=domain-graph]
//
// ebpf-compile comes from the EBPF_COMPILE environment variable, otherwise build/bpf-mlir/bin/ebpf-compile under the module root (PATH is not searched).
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"text/template"

	"github.com/yuskesh/go-bpf-mlir/layout"

	"github.com/yuskesh/go-bpf-mlir/gobpf"
	"github.com/yuskesh/go-bpf-mlir/internal/frontend"
	"github.com/yuskesh/go-bpf-mlir/internal/toolchain"
)

const (
	outMLIR   = "gobpf.mlir"
	outSchema = "gobpf.schema.json"
	outELF    = "gobpf.bpf.o"
	outGen    = "gobpf_gen.go"
)

func main() {
	dir := flag.String("dir", ".", "the package directory")
	emit := flag.String("emit", "", `"domain-graph": print the domain judgement as JSON and write nothing`)
	version := flag.Bool("version", false, "print the go-bpf-mlir version (gobpf.Version and the commit of this build) and the pinned bpf-mlir version, and exit")
	lineInfo := flag.String("line-info", "auto", `"auto": the ELF carries BTF line_info mapping instructions to the Go lines (the verifier log names them), "off": no line_info`)
	flag.Parse()
	if *version {
		fmt.Println(versionLine())
		return
	}
	if *lineInfo != "auto" && *lineInfo != "off" {
		fmt.Fprintf(os.Stderr, "gobpf: -line-info must be auto or off (got %q)\n", *lineInfo)
		os.Exit(2)
	}
	genLineInfo = *lineInfo
	if err := run(*dir, *emit); err != nil {
		fmt.Fprintln(os.Stderr, "gobpf:", err)
		os.Exit(1)
	}
}

// genLineInfo is ebpf-compile's --line-info (the default is auto).
var genLineInfo = "auto"

func run(dir, emit string) error {
	res, err := frontend.AnalyzeWith(dir, frontend.Options{LineInfo: genLineInfo})
	if err != nil {
		return err
	}
	switch emit {
	case "":
	case "domain-graph":
		j, err := res.GraphJSON()
		if err != nil {
			return err
		}
		os.Stdout.Write(j)
		if !res.OK() {
			return errors.New("the package has blocking diagnostics (see the JSON)")
		}
		return nil
	default:
		return fmt.Errorf("unknown -emit %q (known: domain-graph)", emit)
	}
	for _, d := range res.Diagnostics {
		fmt.Fprintln(os.Stderr, d.String())
	}
	if !res.OK() {
		return fmt.Errorf("%d diagnostic(s) — nothing was generated", len(res.Diagnostics))
	}
	if len(res.Programs) == 0 {
		return errors.New("no program found: an xdp program is a top-level func(ctx *bpf.XDPContext) bpf.XDPAction")
	}
	compiler, err := findCompiler(res.ModuleDir)
	if err != nil {
		return err
	}
	// Check the ebpf-compile version against the go.mod version and the submodule — on a mismatch, stop without writing anything (there is no bypass).
	verified, err := toolchain.Check(compiler, res.ModuleDir)
	if err != nil {
		return fmt.Errorf("ebpf-compile version check failed (nothing was generated): %w", err)
	}
	if err := os.WriteFile(filepath.Join(res.Dir, outMLIR), res.MLIR, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(res.Dir, outSchema), res.Schema, 0o644); err != nil {
		return err
	}
	cmd := exec.Command(compiler, outMLIR, "--schema", outSchema, "--line-info="+genLineInfo, "-o", outELF)
	cmd.Dir = res.Dir
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stderr, &stderr
	if err := cmd.Run(); err != nil {
		os.Remove(filepath.Join(res.Dir, outELF))
		// A stack-limit failure in a function that writes a padded ring event gets a named GB016 first (the likely cause); ebpf-compile's text follows as is.
		for _, d := range frontend.StackLimitDiagnostics(res, stderr.String()) {
			fmt.Fprintln(os.Stderr, d.String())
		}
		return fmt.Errorf("ebpf-compile rejected %s (%v):\n%s", filepath.Join(res.Dir, outMLIR), err, toolchain.RewriteLocs(stderr.String(), relDir(res.Dir)))
	}
	// stderr with rc 0: warnings become Conditionals with Go positions (GB024), and a line of unknown shape stops generation (it used to be discarded).
	ws, err := toolchain.CompileWarnings(stderr.String())
	if err != nil {
		os.Remove(filepath.Join(res.Dir, outELF))
		return err
	}
	for _, d := range frontend.CompileWarningDiagnostics(ws) {
		fmt.Fprintln(os.Stderr, d.String())
		res.Diagnostics = append(res.Diagnostics, d) // into the conditional section of the generated file
	}
	elf, err := os.ReadFile(filepath.Join(res.Dir, outELF))
	if err != nil {
		return err
	}
	// Check that the ELF's maps match the declarations (the same check as bpf-mlir's bindgen — the ELF's .maps symbols are authoritative).
	syms, err := layout.MapSymbols(elf)
	if err != nil {
		return fmt.Errorf("reading the maps of %s: %w", outELF, err)
	}
	var want, structOps []string
	for _, m := range res.Maps {
		if m.Kind == "struct_ops" { // a struct_ops map is a .struct_ops.link variable, not in .maps (checked separately below)
			structOps = append(structOps, m.Symbol)
			continue
		}
		want = append(want, m.Symbol)
	}
	if err := checkStructOpsVars(elf, structOps); err != nil {
		return err
	}
	for _, p := range res.Programs {
		if p.ProgramType == "usdt" && p.USDTSpec {
			want = append(want, frontend.USDTSpecMap(p.Symbol)) // the compiler's spec map (not a user map)
		}
	}
	if strings.Join(sorted(want), ",") != strings.Join(syms, ",") {
		return fmt.Errorf("the ELF's maps %v differ from the declared maps %v", syms, sorted(want))
	}
	gen, err := generate(res, compiler, verified)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(res.Dir, outGen), gen, 0o644)
}

// checkStructOpsVars checks that the struct_ops map declarations match the variable symbols in the ELF section `.struct_ops.link`
// (the cilium fork accepts only `.struct_ops.link` — BPF_F_LINK, load does not register. A plain `.struct_ops` section is an error).
func checkStructOpsVars(elfBytes []byte, want []string) error {
	f, err := elf.NewFile(bytes.NewReader(elfBytes))
	if err != nil {
		return fmt.Errorf("reading the ELF for struct_ops: %w", err)
	}
	var got []string
	for _, s := range f.Sections {
		if s.Name == ".struct_ops" {
			return fmt.Errorf("the ELF has a plain .struct_ops section — gobpf needs .struct_ops.link (BPF_F_LINK: loading must not register)")
		}
	}
	syms, err := f.Symbols()
	if err != nil && len(want) > 0 {
		return fmt.Errorf("reading the ELF symbols for struct_ops: %w", err)
	}
	for _, sym := range syms {
		if int(sym.Section) < len(f.Sections) && sym.Section != elf.SHN_UNDEF && f.Sections[sym.Section].Name == ".struct_ops.link" && elf.ST_TYPE(sym.Info) == elf.STT_OBJECT {
			got = append(got, sym.Name)
		}
	}
	if strings.Join(sorted(got), ",") != strings.Join(sorted(want), ",") {
		return fmt.Errorf("the ELF's .struct_ops.link variables %v differ from the declared struct_ops maps %v", sorted(got), sorted(want))
	}
	return nil
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func findCompiler(moduleDir string) (string, error) {
	if p := os.Getenv("EBPF_COMPILE"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("EBPF_COMPILE=%s: %w", p, err)
		}
		return filepath.Abs(p)
	}
	if moduleDir != "" {
		p := filepath.Join(moduleDir, "build", "bpf-mlir", "bin", "ebpf-compile")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("ebpf-compile not found: set EBPF_COMPILE, or build it with scripts/setup.sh (build/bpf-mlir/bin/ebpf-compile) — PATH is not searched")
}

// --- the generated file ---

type provenance struct {
	CompilerPath    string // relative to the module root (external:<basename> if outside) — absolute paths differ per machine
	CompilerSHA256  string
	CompilerVersion string
	BPFMLIRCommit   string
	BPFMLIRGoModule string
	LineInfo        string // ebpf-compile's --line-info (auto / off)
	GobpfVersion    string // the go-bpf-mlir version (gobpf.Version — a constant bumped only in release commits)
	CiliumFork      string // the version of the local cilium/ebpf fork and the submodule commit
	CiliumPatches   string // the upstream changes the fork applied on v0.22.0 (an open PR is named by its head hash)
}

func provenanceOf(moduleDir, compiler string, v toolchain.Verified) provenance {
	var p provenance
	p.CompilerPath = "external:" + filepath.Base(compiler)
	if moduleDir != "" {
		if rel, err := filepath.Rel(moduleDir, compiler); err == nil && !strings.HasPrefix(rel, "..") {
			p.CompilerPath = filepath.ToSlash(rel)
		}
	}
	if b, err := os.ReadFile(compiler); err == nil {
		s := sha256.Sum256(b)
		p.CompilerSHA256 = hex.EncodeToString(s[:])
	}
	// Checked values (after toolchain.Check confirmed that the go.mod version, the submodule and --version agree).
	p.CompilerVersion = fmt.Sprintf("bpf-mlir %s (commit %s) — verified", v.Describe, v.Commit)
	p.BPFMLIRCommit = v.Submodule
	if p.BPFMLIRCommit == "" {
		p.BPFMLIRCommit = "none (no third_party/bpf-mlir in the module — describe and module version checked)"
	}
	p.BPFMLIRGoModule = v.Module
	p.LineInfo = genLineInfo
	p.GobpfVersion = gobpf.Version
	// The cilium/ebpf fork: the version is a constant built into cmd/gobpf, the commit is the HEAD of the module's submodule (the version alone if absent).
	if c, err := toolchain.CiliumForkCommit(moduleDir); err == nil && c != "" {
		p.CiliumFork = fmt.Sprintf("%s (third_party/cilium-ebpf commit %s)", gobpf.CiliumFork, c)
	} else {
		p.CiliumFork = gobpf.CiliumFork + " (no third_party/cilium-ebpf in the module — the version gobpf was built with)"
	}
	p.CiliumPatches = "none"
	if len(gobpf.CiliumForkPatches) > 0 {
		p.CiliumPatches = strings.Join(gobpf.CiliumForkPatches, "; ")
	}
	return p
}

var genTemplate = template.Must(template.New("gen").Parse(`// Code generated by gobpf. DO NOT EDIT.
//
// provenance:
//   go-bpf-mlir:           {{.Prov.GobpfVersion}}
//   ebpf-compile:          {{.Prov.CompilerPath}}
//   ebpf-compile sha256:   {{.Prov.CompilerSHA256}}
//   ebpf-compile version:  {{.Prov.CompilerVersion}}
//   bpf-mlir (submodule):  {{.Prov.BPFMLIRCommit}}
//   bpf-mlir/go (module):  {{.Prov.BPFMLIRGoModule}}
//   cilium/ebpf (fork):    {{.Prov.CiliumFork}}
//   cilium/ebpf patches:   {{.Prov.CiliumPatches}}
//   line-info:             {{.Prov.LineInfo}}
//   schema sha256:         {{.SchemaSHA256}}
//
// declarations (source positions — kept out of the schema so they do not change the ELF):
{{- range .Records}}
//   record  {{.Record.Symbol}} at {{.Record.PosString}}
{{- end}}
{{- range $m := .Maps}}
//   map     {{$m.Symbol}} at {{$m.PosString}}
{{- range $m.Slots}}
//   slot    {{$m.Symbol}}[{{.Index}}] = {{.Program}} at {{.PosString}}
{{- end}}
{{- end}}
{{- range .Programs}}
//   program {{.Symbol}} at {{.PosString}}
{{- end}}
{{- range .Globals}}
//   global  {{.Symbol}} ({{.Section}}) at {{.PosString}}
{{- end}}
{{- if .Conditionals}}
//
// conditional (accepted with a condition — the program is generated, but read these):
{{- range .Conditionals}}
//   {{.}}
{{- end}}
{{- end}}

//go:build linux && amd64 && !gobpf_frontend

package {{.Package}}

import (
	_ "embed"
{{- if .Records}}
	"reflect"
{{- end}}

	"github.com/yuskesh/go-bpf-mlir/gobpf"
{{- if .ImportBPF}}
	"github.com/yuskesh/go-bpf-mlir/bpf"
{{- end}}
)

//go:embed gobpf.bpf.o
var gobpf_elf []byte
{{range .Records}}
// gobpf_{{.Record.Symbol}} is the generated type of record {{.Record.Symbol}} (no methods are added to the user's type).
type gobpf_{{.Record.Symbol}} {{.Record.GoDecodeType}}

// Decode reads by offset (exactly as the schema declares, independent of how Go packs the struct).
func (v *gobpf_{{.Record.Symbol}}) Decode(b []byte) error {
	if len(b) < {{.Size}} {
		return gobpf.ShortRecordError("{{.Record.Symbol}}", len(b), {{.Size}})
	}
{{- range .Record.DecodeLines}}
	{{.}}
{{- end}}
	return nil
}
{{end}}

func init() {
	gobpf.Register(gobpf.Object{
		ELF:          gobpf_elf,
		SchemaSHA256: "{{.SchemaSHA256}}",
		Maps: []gobpf.Map{
{{- range .Maps}}
			{Symbol: "{{.Symbol}}", Var: &{{.Symbol}}, Pos: "{{.PosString}}"},
{{- end}}
		},
		Programs: []gobpf.Program{
{{- range .Programs}}
			{Symbol: "{{.Symbol}}", Kind: "{{.ProgramType}}",{{if .Attach}} Attach: "{{.Attach}}",{{end}} Func: {{.Symbol}}{{if .USDTSpec}}, USDTSpec: {{.USDTMaxPoints}}{{end}}{{if .IterMap}}, IterMap: "{{.IterMap}}"{{end}}{{if .ExtTarget}}, ExtTarget: "{{.ExtTarget}}"{{end}}{{if .PerfMaps}}, PerfMaps: []string{ {{- range $i, $m := .PerfMaps}}{{if $i}}, {{end}}"{{$m}}"{{end -}} }{{end}}},
{{- end}}
		},
{{- if .Records}}
		Records: []gobpf.Record{
{{- range .Records}}
			{Symbol: "{{.Record.Symbol}}", Size: {{.Size}}, Type: reflect.TypeFor[{{.Record.GoType}}](), New: func() gobpf.Decoder { return new(gobpf_{{.Record.Symbol}}) }},
{{- end}}
		},
		MapValues: []gobpf.MapValue{
{{- range .MapValueRows}}
			{Map: "{{.Map}}", Record: "{{.Record}}"{{if .Member}}, Member: "{{.Member}}"{{end}}},
{{- end}}
		},
{{- if .RingBufs}}
		RingBufRecords: []gobpf.MapValue{
{{- range .RingBufs}}
			{Map: "{{.Symbol}}", Record: "{{.Value.Record.Symbol}}"},
{{- end}}
		},
{{- end}}
{{- if .PerfEvents}}
		PerfRecords: []gobpf.MapValue{
{{- range .PerfEvents}}
			{Map: "{{.Symbol}}", Record: "{{.Event.Record.Symbol}}"},
{{- end}}
		},
{{- end}}
{{- end}}
{{- if .Globals}}
		Globals: []gobpf.Global{
{{- range .Globals}}
			{Symbol: "{{.Symbol}}", Var: &{{.Symbol}}, Pos: "{{.PosString}}"},
{{- end}}
		},
{{- end}}
{{- if .TailSlots}}
		TailSlots: []gobpf.TailSlot{
{{- range .TailSlots}}
			{Map: "{{.Map}}", Slot: {{.Slot}}, Program: "{{.Program}}", Pos: "{{.Pos}}"},
{{- end}}
		},
{{- end}}
	})
}
`))

func generate(res *frontend.Result, compiler string, verified toolchain.Verified) ([]byte, error) {
	sum := sha256.Sum256(res.Schema)
	var buf bytes.Buffer
	err := genTemplate.Execute(&buf, map[string]any{
		"Prov":         provenanceOf(res.ModuleDir, compiler, verified),
		"SchemaSHA256": hex.EncodeToString(sum[:]),
		"Package":      res.PkgName,
		"Maps":         res.Maps,
		"Records":      res.Records,
		"RingBufs":     ringBufs(res.Maps),
		"PerfEvents":   perfEvents(res.Maps),
		"MapValueRows": mapValueRows(res.Maps),
		"Conditionals": conditionals(res),
		"Programs":     res.Programs,
		"TailSlots":    tailSlots(res.Maps),
		"Globals":      res.Globals,
		"ImportBPF":    importsBPF(res.Records),
	})
	if err != nil {
		return nil, err
	}
	return format.Source(buf.Bytes())
}

// relDir makes dir relative to the current directory (for display — unchanged if it cannot be made relative).
func relDir(dir string) string {
	wd, err := os.Getwd()
	if err != nil {
		return dir
	}
	if rel, err := filepath.Rel(wd, dir); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return dir
}

// ringBufs returns the ring buffer maps (RingBufRecords in the generated file). User ring buffers too (their BTF map definition has no value member).
func ringBufs(ms []*frontend.BpfMap) []*frontend.BpfMap {
	var out []*frontend.BpfMap
	for _, m := range ms {
		if m.Kind == "ringbuf" || m.Kind == "user_ringbuf" {
			out = append(out, m)
		}
	}
	return out
}

type mapValueRow struct{ Map, Record, Member string }

// mapValueRows returns the rows of maps whose key / value is a record (MapValues in the generated file — layout.CheckMapValues checks them against the ELF BTF .maps).
// A key row has Member "key" (the same shape as bpf-mlir's bindgen). Ring buffers go to RingBufRecords.
func mapValueRows(ms []*frontend.BpfMap) []mapValueRow {
	var out []mapValueRow
	for _, m := range ms {
		if m.Kind == "ringbuf" || m.Kind == "user_ringbuf" { // user_ringbuf too
			continue
		}
		if m.Key.IsRecord() {
			out = append(out, mapValueRow{m.Symbol, m.Key.Record.Symbol, "key"})
		}
		if m.Value.IsRecord() {
			out = append(out, mapValueRow{m.Symbol, m.Value.Record.Symbol, ""})
		}
	}
	return out
}

// conditionals returns the text of the Conditional diagnostics (a comment in the generated file — they do not stop generation, but they are never silent).
func conditionals(res *frontend.Result) []string {
	var out []string
	for _, d := range res.Diagnostics {
		if d.Verdict == frontend.Conditional {
			out = append(out, d.String())
		}
	}
	return out
}

// genTailSlot is one row of TailSlots in the generated file.
type genTailSlot struct {
	Map, Program, Pos string
	Slot              uint64
}

// tailSlots returns the prog_array slot declarations (in map declaration order, by index within a map — the same order as the schema slots).
func tailSlots(ms []*frontend.BpfMap) []genTailSlot {
	var out []genTailSlot
	for _, m := range ms {
		for _, s := range m.Slots {
			out = append(out, genTailSlot{Map: m.Symbol, Program: s.Program, Pos: s.PosString(), Slot: s.Index})
		}
	}
	return out
}

// importsBPF reports whether the generated file names a type from the bpf package (a record the bpf package owns — the LPMTrie4 key).
func importsBPF(rs []*frontend.SharedABI) bool {
	for _, r := range rs {
		if r.Record.GoExpr != "" {
			return true
		}
	}
	return false
}

// perfEvents returns the perf_event_array maps (PerfRecords in the generated file).
func perfEvents(ms []*frontend.BpfMap) []*frontend.BpfMap {
	var out []*frontend.BpfMap
	for _, m := range ms {
		if m.Kind == "perf_event_array" {
			out = append(out, m)
		}
	}
	return out
}

// versionLine is the -version line: gobpf.Version (the release constant), this build's commit (the vcs from build info, otherwise git describe of
// the module source — -version goes down to the commit) and the version of the pinned bpf-mlir Go module.
func versionLine() string {
	commit, bpfmlir := "", "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		rev, dirty := "", ""
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if rev != "" {
			commit = rev[:min(12, len(rev))] + dirty
		}
	}
	if v, err := toolchain.BuildModuleVersion(); err == nil {
		bpfmlir = v
	}
	if commit == "" {
		// go tool / go run may not stamp vcs — git describe of the source directory (the module containing this file).
		if _, file, _, ok := runtime.Caller(0); ok {
			if out, err := exec.Command("git", "-C", filepath.Dir(file), "describe", "--tags", "--always", "--dirty").Output(); err == nil {
				commit = strings.TrimSpace(string(out))
			}
		}
	}
	if commit == "" {
		commit = "unknown commit"
	}
	return fmt.Sprintf("gobpf %s (%s) — bpf-mlir/go %s", gobpf.Version, commit, bpfmlir)
}
