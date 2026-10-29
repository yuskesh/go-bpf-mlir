package gobpf

// Version is the go-bpf-mlir version. **It is raised by hand only in a release commit** — it is not the git describe value (it goes into the provenance of the generated files,
// so that every gobpf_gen.go does not change on every commit and the goldens stay stable). "v0.0.0" was before the first release (v0.1.0).
// The version rules are in docs/release.md.
const Version = "v0.17.0"
