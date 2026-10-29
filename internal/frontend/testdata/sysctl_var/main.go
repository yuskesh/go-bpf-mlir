package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SetNewValue takes only a string constant — a variable is outside (string values are outside capability go.string — GB011 stops at the variable).
func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
	s := "63\n"
	ctx.SetNewValue(s)
	return bpf.CgroupAllow
}

func main() {}
