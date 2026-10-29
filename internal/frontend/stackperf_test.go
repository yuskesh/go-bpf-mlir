package frontend

import (
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// `_ =` makes the choice not to count explicit — it is not GB017, and reuse and KernelID inside a record are lowered too.
func TestStackPerfDiscardOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "sp_discard_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("sp_discard_ok was not accepted")
	}
	mlir := string(res.MLIR)
	for _, want := range []string{
		`ebpf.stack.kernel_id %ctx, %m0 skip 2 reuse : !ebpf.ctx<"fentry">, !ebpf.map<"stack_trace", i32, !ebpf.stack<8>> -> i64`,
		`ebpf.stack.kernel_id %ctx, %m0 skip 0 : !ebpf.ctx<"fentry">, !ebpf.map<"stack_trace", i32, !ebpf.stack<8>> -> i64`,
		`ebpf.perf.output %ctx, %m1, `,
	} {
		if !strings.Contains(mlir, want) {
			t.Errorf("the .mlir lacks %q:\n%s", want, mlir)
		}
	}
	schema := string(res.Schema)
	for _, want := range []string{`"kind": "perf_event_array"`, `"max_entries": 0`, `"record": "Ev"`, `"count": 8`} {
		if !strings.Contains(schema, want) {
			t.Errorf("the schema lacks %s", want)
		}
	}
}

// if forms for Init's status — accepts `if p.T.Init() == 0` and `st := p.T.Init()` in an earlier statement checked by a later `if 0 == st`.
func TestTimerGuardFormsOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "timer_guard_forms_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("timer_guard_forms_ok was not accepted")
	}
	mlir := string(res.MLIR)
	for _, want := range []string{"ebpf.timer.callback @onFire map @Wins", `ebpf.timer.set_callback %`, `ebpf.timer.start %`, "ebpf.timer.done"} {
		if strings.Count(mlir, want) == 0 {
			t.Errorf("the .mlir lacks %q", want)
		}
	}
	if n := strings.Count(mlir, "ebpf.timer.start %"); n != 2 {
		t.Errorf("%d timer.start, want 2", n)
	}
}

// Declaring the type of an earlier unread argument with `_ = bpf.TPArg[T](ctx, j)` — the schema's args is a positional array holding every i,
// and ctx.arg appears only for arguments that are read.
func TestTPArgDeclOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "tp_decl_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || res.MLIR == nil {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("tp_decl_ok was not accepted")
	}
	mlir, schema := string(res.MLIR), string(res.Schema)
	if strings.Count(mlir, "ebpf.ctx.arg") != 1 || !strings.Contains(mlir, `ebpf.ctx.arg %ctx[1] : !ebpf.ctx<"tp_btf"> -> !ebpf.kptr<"task_struct">`) || !strings.Contains(mlir, `ebpf.kfield.load`) {
		t.Errorf("want one ctx.arg (argument 1) and a kfield.load:\n%s", mlir)
	}
	if !strings.Contains(schema, "\"args\": [\n          \"task_struct\",\n          \"task_struct\"\n        ]") || !strings.Contains(schema, `"kernel_types"`) {
		t.Errorf("want args [task_struct, task_struct] and kernel_types in the schema:\n%s", schema)
	}
}

// Checks whether the defect where callOp missed generic calls with explicit type arguments (call.Fun is an IndexExpr) also hid other generic
// API checks — rewrites the generic API calls in negative cases written with inferred type arguments into the explicit form, and
// checks they stop with the same code and message (the KprobeArg / UprobeArg / TPArg negative cases are already explicit — not inferable / written explicitly).
func TestExplicitTypeArgsSameDiagnostics(t *testing.T) {
	checked := 0
	for _, c := range negativeCases {
		dir := caseDir(c.dir)
		res, err := analyzeCached(dir)
		if err != nil || res.an == nil || res.an.info == nil {
			continue
		}
		// Calls to bpf generic functions with inferred type arguments (identifier → type argument string).
		src, err := os.ReadFile(filepath.Join(dir, "main.go"))
		if err != nil {
			continue
		}
		type edit struct {
			off  int
			text string
		}
		var edits []edit
		for id, inst := range res.an.info.Instances {
			obj := res.an.info.Uses[id]
			if obj == nil || !inAPIPackage(obj) || inst.TypeArgs == nil || inst.TypeArgs.Len() == 0 {
				continue
			}
			if _, isFn := obj.(*types.Func); !isFn {
				continue
			}
			pos := res.an.fset.Position(id.End())
			if !strings.HasSuffix(pos.Filename, "main.go") || pos.Offset >= len(src) || src[pos.Offset] == '[' {
				continue // already explicit
			}
			var args []string
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				args = append(args, types.TypeString(inst.TypeArgs.At(i), types.RelativeTo(res.an.pkg.Types)))
			}
			edits = append(edits, edit{pos.Offset, "[" + strings.Join(args, ", ") + "]"})
		}
		if len(edits) == 0 {
			continue
		}
		sort.Slice(edits, func(i, j int) bool { return edits[i].off > edits[j].off })
		out := string(src)
		for _, e := range edits {
			out = out[:e.off] + e.text + out[e.off:]
		}
		tmp := filepath.Join("testdata", "zz_explicit_"+c.dir)
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmp)
		if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		res2, err := Analyze(tmp)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, d := range res2.Diagnostics {
			if d.Code == c.code && d.Verdict == c.verdict && strings.Contains(d.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			for _, d := range res2.Diagnostics {
				t.Log(d.String())
			}
			t.Errorf("%s with explicit type arguments (%d calls) no longer stops with %s %q", c.dir, len(edits), c.code, c.msg)
		}
		checked++
		t.Logf("%s: %d generic calls made explicit — same %s", c.dir, len(edits), c.code)
	}
	if checked == 0 {
		t.Fatal("no negative case calls a generic API with inferred type arguments — the check is vacuous")
	}
}
