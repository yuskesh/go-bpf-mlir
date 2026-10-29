//go:build linux

package kload

import (
	"io"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// UprobeDebugFile does no kernel probing. Its immutable byte snapshot lives
// through Check; the file is closed before returning, not retained for attach.
func (c LiveCaps) UprobeDebugFile(program string, id []byte) (io.ReaderAt, error) {
	if path, ok := c.UprobeDebugPaths[program]; ok {
		return requirements.ReadUprobeDebugFile(path)
	}
	root := "/usr/lib/debug"
	if c.UprobeDebugRoot != nil {
		root = *c.UprobeDebugRoot
	}
	path, err := requirements.BuildIDDebugPath(root, id)
	if err != nil {
		return nil, err
	}
	return requirements.ReadUprobeDebugFile(path)
}
