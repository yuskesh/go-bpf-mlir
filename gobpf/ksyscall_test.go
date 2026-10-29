package gobpf

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// The attach is bpf-mlir's livecaps.AttachKsyscall (checking the attached target and refusing a machine with an unknown prefix are unit-tested by bpf-mlir's
// kernel/livecaps TestAttachKsyscallChecks). gobpf wraps the error with `gobpf.AttachKsyscall: program <symbol>: ` and keeps the text
// (livecaps' check message). A fake of the live glue (a wrong attach target — the same shape as livecaps' message) tests the wrapping.
func TestAttachKsyscallWrapsLiveErrors(t *testing.T) {
	if reflect.ValueOf(attachKsyscallLive).Pointer() != reflect.ValueOf(livecaps.AttachKsyscall).Pointer() {
		t.Fatal("attachKsyscallLive is not livecaps.AttachKsyscall — gobpf must attach ksyscall through bpf-mlir's glue")
	}
	live := func(p *ebpf.Program, syscall string) (link.Link, error) {
		return nil, fmt.Errorf("AttachKsyscall: attached to sys_%s, not the syscall wrapper __x64_sys_%s (the loader substituted another symbol); detached", syscall, syscall)
	}
	l, err := attachKsyscallEntry("onGetppid", "getppid", nil, live)
	want := "gobpf.AttachKsyscall: program onGetppid: AttachKsyscall: attached to sys_getppid, not the syscall wrapper __x64_sys_getppid (the loader substituted another symbol); detached"
	if l != nil || err == nil || err.Error() != want {
		t.Fatalf("attachKsyscallEntry = %v, %v; want the error %q", l, err, want)
	}
	if !strings.Contains(err.Error(), "not the syscall wrapper") {
		t.Fatalf("the wrapped error lost livecaps' text: %v", err)
	}
}

// gobpf's declared ksyscall_attach comes from bpf-mlir's preset cilium-v0.22-ksyscall (the value is prefix, the same as before).
func TestLoaderDeclKsyscallFromPreset(t *testing.T) {
	if LoaderDecl.KsyscallAttach != requirements.Cilium022Ksyscall.KsyscallAttach || livecaps.KsyscallLoader.KsyscallAttach != requirements.KsyscallAttachPrefix {
		t.Fatalf("gobpf.LoaderDecl.KsyscallAttach = %q, preset Cilium022Ksyscall %q, livecaps.KsyscallLoader %q — want all prefix",
			LoaderDecl.KsyscallAttach, requirements.Cilium022Ksyscall.KsyscallAttach, livecaps.KsyscallLoader.KsyscallAttach)
	}
}

// gobpf's loader declaration differs from the cilium v0.22 declaration (requirements.Cilium022)
// only in six fields: the name, ksyscall_attach, usdt_attach, sockmap_attach, lsm_cgroup_load and fsession_load (the cilium fork) — the other
// properties (kprobe aliases, path reopening, CO-RE, BTF rewriting) are cilium's own. usdt_attach is ref_ctr, the same as bpf-mlir's glue declaration (livecaps.USDTLoader =
// Cilium022USDT); sockmap_attach is prog_attach, the same as bpf-mlir's PROG_ATTACH declaration (livecaps.SockmapProgAttachLoader = Cilium022ProgAttach).
func TestLoaderDeclDiffersInSixFields(t *testing.T) {
	want := requirements.Cilium022
	want.Name = wantLoaderName // differs by the cilium of the build (fork_test.go / fork_upstream_test.go)
	want.KsyscallAttach = requirements.KsyscallAttachPrefix
	want.USDTAttach = requirements.USDTAttachRefCtr
	want.SockmapAttach = requirements.SockmapAttachProgAttach
	want.LSMCgroupLoad = requirements.ProgLoadBTFID
	want.FsessionLoad = wantFsessionLoad // differs by the cilium of the build
	if !reflect.DeepEqual(LoaderDecl, want) {
		t.Fatalf("gobpf.LoaderDecl = %+v, want Cilium022 with only the name, ksyscall_attach, usdt_attach, sockmap_attach, lsm_cgroup_load and fsession_load changed: %+v", LoaderDecl, want)
	}
	if requirements.Cilium022.FsessionLoad != requirements.ProgLoadNone {
		t.Fatalf("Cilium022.FsessionLoad = %q — the premise (cilium v0.22 cannot load fsession) changed", requirements.Cilium022.FsessionLoad)
	}
	if requirements.Cilium022.LSMCgroupLoad != requirements.ProgLoadNone {
		t.Fatalf("Cilium022.LSMCgroupLoad = %q — the premise (cilium v0.22 cannot load lsm_cgroup) changed", requirements.Cilium022.LSMCgroupLoad)
	}
	if requirements.Cilium022.SockmapAttach != requirements.SockmapAttachLink {
		t.Fatalf("Cilium022.SockmapAttach = %q — the premise (cilium v0.22 attaches sk_skb / sk_msg with a sockmap link) changed", requirements.Cilium022.SockmapAttach)
	}
	if livecaps.SockmapProgAttachLoader.SockmapAttach != requirements.SockmapAttachProgAttach || requirements.Cilium022ProgAttach.SockmapAttach != requirements.SockmapAttachProgAttach {
		t.Fatalf("bpf-mlir's PROG_ATTACH glue declares sockmap_attach %q (Cilium022ProgAttach %q), not prog_attach — gobpf's declaration copies it", livecaps.SockmapProgAttachLoader.SockmapAttach, requirements.Cilium022ProgAttach.SockmapAttach)
	}
	if requirements.Cilium022.KsyscallAttach != requirements.KsyscallAttachNone {
		t.Fatalf("Cilium022.KsyscallAttach = %q — the premise (cilium v0.22 does not attach ksyscall to the wrapper) changed", requirements.Cilium022.KsyscallAttach)
	}
	if requirements.Cilium022.USDTAttach != requirements.USDTAttachNone {
		t.Fatalf("Cilium022.USDTAttach = %q — the premise (cilium v0.22 does not attach USDT points) changed", requirements.Cilium022.USDTAttach)
	}
	if livecaps.USDTLoader.USDTAttach != requirements.USDTAttachRefCtr || requirements.Cilium022USDT.USDTAttach != requirements.USDTAttachRefCtr {
		t.Fatalf("bpf-mlir's USDT glue declares usdt_attach %q (Cilium022USDT %q), not ref_ctr — gobpf's declaration copies it", livecaps.USDTLoader.USDTAttach, requirements.Cilium022USDT.USDTAttach)
	}
}
