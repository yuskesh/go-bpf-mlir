# go-bpf-mlir

A frontend that compiles a restricted subset of Go to eBPF. From Go source it emits `.mlir` in the MLIR dialect `ebpf` of [bpf-mlir](https://github.com/yuskesh/bpf-mlir)
and a schema JSON, and bpf-mlir's `ebpf-compile` turns them into a BPF ELF with BTF. One Go program holds both the eBPF side and the user-space side, and builds into one binary
(the ELF is embedded with `go:embed`, and typed bindings are generated for load, attach and map access).

- Versions and compatibility (the v0.x promise, frozen reason codes, the bpf-mlir version pairing): [docs/release.md](docs/release.md)
- **What you can write (reference)**: start at [docs/reference/notes.md](docs/reference/notes.md) — API ([api.md](docs/reference/api.md)), program kinds ([kinds.md](docs/reference/kinds.md)),
  reason codes and fixes ([codes.md](docs/reference/codes.md)), examples ([examples.md](docs/reference/examples.md)), emitted ops ([ops.md](docs/reference/ops.md)),
  **supported scope ([scope.md](docs/reference/scope.md))**, and what is outside the scope or has known limits ([limits.md](docs/reference/limits.md)).
  The generated pages are built from the frontend's own tables
- Loading as a non-root user (required capabilities per program kind and map): [docs/nonroot.md](docs/nonroot.md)

## Requirements

- Linux x86_64
- Go 1.26 or later
- `ebpf-compile` built from the bpf-mlir v1.22.0 source release (it needs LLVM / MLIR 23.1.1), pointed to by `EBPF_COMPILE`.
  The generated code checks that the `ebpf-compile` version matches the bpf-mlir version this module pairs with ([docs/release.md](docs/release.md))

## Build and run an example

```sh
export EBPF_COMPILE=/path/to/ebpf-compile
go build ./...
go generate ./examples/xdpcount          # writes the .mlir, schema, ELF and gobpf_gen.go
go build -o xdpcount ./examples/xdpcount
sudo ./xdpcount -selftest 5              # load, test run and map read check (root — for non-root see docs/nonroot.md)
```

The examples, with their kinds and maps, are listed in [docs/reference/examples.md](docs/reference/examples.md); the `-selftest` arguments are in each example's package doc comment.
The generated files (`gobpf.*`, `gobpf_gen.go`) are committed, and running `go generate` again reproduces them byte for byte.

## Use it in your own module — [tutorial](docs/tutorial.md)

From scratch in a new module: getting the module and `ebpf-compile`, a first program, running without root (setcap / setpriv), reading diagnostics,
ring buffer events, and tcx with the packet-window helpers.

The provenance lines in the generated files record the `ebpf-compile` version, which is checked against the bpf-mlir version this module pairs with.

**cilium/ebpf**: this module requires upstream cilium/ebpf (main at b5a5a86f). One program kind, `fsession`, needs cilium/ebpf support that upstream does not have yet;
with upstream cilium/ebpf, `gobpf.Load` of an object that holds an fsession program stops before loading anything (the target check reports that the loader
cannot load an fsession program), and `gobpf.AttachFsession` returns a named error.

## License

Apache-2.0 WITH LLVM-exception. Copyright (c) 2026 Yusuke Shinozaki.
