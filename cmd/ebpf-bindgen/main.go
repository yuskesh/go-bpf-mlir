// ebpf-bindgen generates typed cilium/ebpf bindings from the canonical schema:
//   ebpf-bindgen --schema schema.json --object program.bpf.o --output objects_gen.go
// Generated Go embeds the ELF and needs neither cgo, C sources nor MLIR.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/bindgen"
	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

func main() {
	schemaPath := flag.String("schema", "", "canonical schema (JSON)")
	objectPath := flag.String("object", "", "BPF ELF with BTF to embed")
	outputPath := flag.String("output", "", "generated Go file")
	pkg := flag.String("package", "", "generated Go package name (default: output directory name)")
	flag.Parse()

	if *schemaPath == "" || *objectPath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: ebpf-bindgen --schema S --object O --output F")
		os.Exit(2)
	}
	name := *pkg
	if name == "" {
		name = filepath.Base(filepath.Dir(mustAbs(*outputPath)))
	}

	schema, err := os.ReadFile(*schemaPath)
	if err != nil {
		die("cannot read schema: %v", err)
	}
	// go:embed paths must be relative to the generated Go file.
	rel, err := filepath.Rel(filepath.Dir(mustAbs(*outputPath)), mustAbs(*objectPath))
	if err != nil {
		die("cannot make a relative ELF path: %v", err)
	}
	if _, err := os.Stat(*objectPath); err != nil {
		die("ELF is missing (run ebpf-compile first): %v", err)
	}

	// Independently hash the schema bytes and check the hash stored by
	// ebpf-compile. Refuse generation from a different schema.
	sum := sha256.Sum256(schema)
	hash := hex.EncodeToString(sum[:])
	f, err := os.Open(*objectPath)
	if err != nil {
		die("cannot open ELF: %v", err)
	}
	req, err := requirements.FromELF(f)
	f.Close()
	if err != nil {
		die("cannot read ELF requirements: %v", err)
	}
	if req.SchemaSHA256 != hash {
		die("ELF (%s) was built from schema %s, but the supplied schema (%s) is %s — rerun ebpf-compile with this schema",
			*objectPath, req.SchemaSHA256, *schemaPath, hash)
	}

	// After hash validation and before generation, require schema maps to exist
	// as ELF .maps symbols and agree with requirements map rows.
	elfBytes, err := os.ReadFile(*objectPath)
	if err != nil {
		die("cannot read ELF: %v", err)
	}
	elfMaps, err := layout.MapSymbols(elfBytes)
	if err != nil {
		die("cannot read ELF maps: %v", err)
	}
	// struct_ops maps are .struct_ops.link globals, not .maps entries.
	// cilium turns these symbols into StructOpsMap specs.
	sops, err := layout.StructOpsTables(elfBytes)
	if err != nil {
		die("cannot read the ELF struct_ops table: %v", err)
	}
	for n := range sops {
		elfMaps = append(elfMaps, n)
	}
	sort.Strings(elfMaps)
	var reqMaps []string
	for _, m := range req.Maps {
		reqMaps = append(reqMaps, m.Symbol)
	}
	if err := bindgen.CheckSchemaMapsInELF(schema, elfMaps, reqMaps); err != nil {
		die("%v", err)
	}

	out, err := bindgen.Generate(bindgen.Input{
		Package: name, SchemaJSON: schema, ObjectPath: rel, SchemaSHA256: hash,
	})
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(*outputPath, out, 0o644); err != nil {
		die("cannot write: %v", err)
	}
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		die("%v", err)
	}
	return a
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ebpf-bindgen: "+format+"\n", a...)
	os.Exit(1)
}
