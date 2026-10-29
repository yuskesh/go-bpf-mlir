# Versions and compatibility

How go-bpf-mlir versions are numbered, what stays compatible during v0.x, and which bpf-mlir each version is paired with. The supported scope is in [reference/scope.md](reference/scope.md).

## What a version means

- **v0.x does not promise API compatibility** (the same as bpf-mlir). The public identifiers of `bpf` / `gobpf` and the shape of generated files can change between versions. Changes are written in the version history (below)
- **What v0.x does keep**:
  1. **Reason code numbers and names are only added** — the table in [reference/codes.md](reference/codes.md) is frozen. An existing code keeps its number and name, is never removed, and its number is never reused; a new code is appended with the next number. A frontend test checks the codes against the frozen table, and checks that the table of the last release tag is the head of the current table
  2. **Old generated files do not run silently** — after upgrading, run `go generate` again. A binary built without regenerating stops, by name, at one of these points:
     - at generate: gobpf checks that ebpf-compile was built from the bpf-mlir commit this version pins (on a mismatch nothing is written)
     - at build: if a gobpf type or field used by the generated `gobpf_gen.go` changed, Go reports a compile error
     - before Load (without touching the kernel — `verifyEmbedded`): the schema's SHA-256 and the ELF's `.ebpf_requirements` (bindrt.CheckSchema), record layouts, map and global declarations (bindrt.CheckMapDecls — both directions) and tail call slots. A build that changed only the Go declarations without regenerating also stops
  3. **How a breaking change is written** — the version history entry has three lines: what, why, and how to migrate. A change in the meaning of a reason code is a breaking change (add a new number and keep the old code)
- **`gobpf.Version`** (`gobpf/version.go`) is a **constant raised by hand only in release commits** — it goes into the `go-bpf-mlir:` provenance line of generated files (it is not git describe, so that every `gobpf_gen.go` does not change on every commit). `gobpf -version` prints the constant, the commit of this build (vcs build info, or git describe of the source) and the pinned bpf-mlir version

## The bpf-mlir pair

Each go-bpf-mlir version is built and tested with one bpf-mlir pair, and the pair changes only in a go-bpf-mlir release (with the pinned commit, the copied packages and the provenance lines of the generated files together):

- **ebpf-compile**: built from the **bpf-mlir v1.20.0 source release** (commit `d3e13842326f4dd2006b2f5528a3c9b6f409caf7`). `go generate` finds it through `EBPF_COMPILE`, and stops with a named error (writing nothing) when ebpf-compile was built from any other commit
- **bpf-mlir Go packages**: the binding packages of bpf-mlir (bindrt, requirements, layout, livecaps and the packages they use, and ebpf-bindgen) are copied into this module from the same bpf-mlir commit (`d3e13842`), with their import paths under `github.com/yuskesh/go-bpf-mlir`. The Go-free source release does not ship them, and there is no separate bpf-mlir Go module to fetch (see NOTICE)
- **cilium/ebpf**: upstream main at commit b5a5a86f (the pseudo-version in go.mod). fsession programs need cilium/ebpf's fsession support (#2108), which is not in upstream — with upstream cilium/ebpf, gobpf stops them with a named error
- **Toolchain**: Go 1.26 or later; LLVM / MLIR 23.1.1 to build ebpf-compile; Linux x86_64

## Tags and getting go-bpf-mlir

- Tags are annotated tags `vX.Y.Z` at the module root (there are no nested modules). A version is published only as its tag: there is no separate source tarball and no signature
- Get a version with `go get github.com/yuskesh/go-bpf-mlir@vX.Y.Z`, and build ebpf-compile from the paired bpf-mlir source release ([tutorial](tutorial.md), step 0)
- In a release commit: `gobpf.Version` is raised, the generated files are regenerated (provenance line), an entry is added to the version history, and the README and tutorial steps are checked from a new module

## Version history

### v0.18.0 — user strings, kernel field paths, split DWARF and uprobe buffers

- **Scope**: 85 feature groups (78 in v0.17.0) — new: user strings from tracepoint fields and ksyscall arguments (G79), argv arrays (G80), tracepoint byte arrays (G81),
  kernel field paths through embedded kernel types (G82), kernel pointer addresses (G83), split DWARF of uprobe targets (G84), uprobe user buffers and raw pointers (G85).
  9 of the 85 are limited ([reference/scope.md](reference/scope.md))
- **New API**: `bpf.KsyscallStr`, `bpf.KsyscallStrArray`, `bpf.UserStrArray` (`At`), `bpf.KernelAddr`, `bpf.UserBuf`, `bpf.UprobeBuf`, `RingBuf.OutputBuf`;
  tracepoint event fields of type `bpf.UserStr`, `bpf.UserStrArray`, `[N]byte` / `[N]int8`; `gobpf.WithUprobeDebugRoot`, `gobpf.WithUprobeDebugFile`
- **Breaking — `bpf.UserStr` is 8 bytes** (it was 0):
  - What: `bpf.UserStr` now has the size and alignment of a pointer (8 bytes)
  - Why: a `char *` field of a tracepoint event struct is a `bpf.UserStr`, and the event struct must have the C layout
  - How to migrate: only Go code that measures a struct holding a `bpf.UserStr` is affected — a `bpf.UserStr` is never a field of a map or ring buffer record (generate rejects it)
- **Changed**: `bpf.UprobeArg` accepts `uintptr` (`uint64(bpf.UprobeArg[uintptr](ctx, n))` — a raw pointer value checked against the binary's DWARF)
- **Fixed**: the non-root hint after a refused capability probe names the program kinds and their capabilities (root only for tracepoint and ksyscall, CAP_SYS_ADMIN for uprobe / uretprobe / usdt, CAP_PERFMON for the other tracing kinds)
- **Fixed**: an ebpf-compile stack-limit failure in a function that writes a ring buffer event with `_` padding gets a GB016 naming the padding as the likely cause (name the padding field)
- **Reason codes**: unchanged (GB000 to GB029)
- **Dependencies**: unchanged — the bpf-mlir pair above (v1.20.0, commit d3e13842), cilium/ebpf upstream main b5a5a86f, Go 1.26 or later, LLVM / MLIR 23.1.1
- **Getting it**: `go get github.com/yuskesh/go-bpf-mlir@v0.18.0`, then run `go generate` again (only the provenance line of the generated files changes)

### v0.17.0 — the first public version

- **First public version.** The versions before it (v0.1.0 to v0.16.0) were development versions and were not published, so this entry does not list changes from them. The promises above (the frozen reason code table, old generated files failing by name) hold from this version
- **Scope**: the **78 feature groups** of [reference/scope.md](reference/scope.md) — each is **supported** (frontend negative examples, a differential or selftest run on the 3 kernels 7.1.8 / 6.12.111 / 6.6.157, and a row in the non-root capability matrix) or **limited** (naming what is missing). What is outside the scope and the known limits are in [reference/limits.md](reference/limits.md); the capabilities a non-root loader needs are in [nonroot.md](nonroot.md)
- **Reason codes**: GB000 to GB029 ([reference/codes.md](reference/codes.md) — frozen from this version)
- **Dependencies**: the bpf-mlir pair above (ebpf-compile from the bpf-mlir v1.20.0 source release, commit d3e13842; the Go binding packages copied from the same commit), cilium/ebpf upstream main b5a5a86f, Go 1.26 or later, LLVM / MLIR 23.1.1
- **Getting it**: `go get github.com/yuskesh/go-bpf-mlir@v0.17.0`, and `EBPF_COMPILE` pointing at an ebpf-compile built from the bpf-mlir v1.20.0 source release ([tutorial](tutorial.md), step 0)
- **fsession** (G55): loads only with a cilium/ebpf that has fsession support; with the upstream cilium/ebpf this module requires, gobpf stops it with a named error
