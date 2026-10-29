package main

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// The -selftest expected table (a hand-written oracle) matches the eBPF side's classify and the program's length rule evaluated in Go.
// This file is outside the frontend's analysis (Tests: false), so it can call the eBPF-side functions with Go semantics. It does not use the kernel.
func TestSelftestTableMatchesClassify(t *testing.T) {
	for _, f := range selftestFrames() {
		key := KShort
		if len(f.frame) >= 14 {
			et := binary.BigEndian.Uint16(f.frame[12:])
			key = classify(et, 0)
			if et == 0x0800 {
				key = KIPv4Short
				if len(f.frame) >= 24 {
					key = classify(et, f.frame[23])
				}
			}
		}
		if key != f.key {
			t.Errorf("%s: the table says %s, classify says %s", f.name, keyNames[f.key], keyNames[key])
		}
	}
}

// TestSameBody checks that the bodies of the three programs are the same statements except the last two (the AtomicAdd to the direction index and the return)
// (a context cannot be passed to a subprogram — GB013 — so each program does its own window reads).
func TestSameBody(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]string{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || (fd.Name.Name != "countXDP" && fd.Name.Name != "countIngress" && fd.Name.Name != "countEgress") {
			continue
		}
		var b bytes.Buffer
		stmts := fd.Body.List
		for _, s := range stmts[:len(stmts)-2] {
			printer.Fprint(&b, fset, s)
			b.WriteString("\n")
		}
		body[fd.Name.Name] = b.String()
	}
	if len(body) != 3 || body["countXDP"] != body["countIngress"] || body["countXDP"] != body["countEgress"] {
		t.Fatalf("the bodies of the three programs differ (apart from the last two statements): %q", body)
	}
}
