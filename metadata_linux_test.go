package main

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalCopyRefusesUnverifiedExtendedAttributes(t *testing.T) {
	e := newTestEnv(t)
	src := filepath.Join(e.Root, "attrs-source")
	removalWrite(t, filepath.Join(src, "file"), "content")
	for _, p := range []string{src, filepath.Join(src, "file")} {
		err := syscall.Setxattr(p, "user.fixture", []byte("retained"), 0)
		if err == syscall.ENOTSUP {
			t.Skip("fixture filesystem does not support extended attributes")
		}
		must(t, err)
	}
	dest := filepath.Join(e.Root, "attrs-copy")
	err := e.A.copyTree(src, dest)
	check(t, err != nil, "extended data copied without verification")
	for _, p := range []string{src, filepath.Join(src, "file")} {
		value := make([]byte, 32)
		n, err := syscall.Getxattr(p, "user.fixture", value)
		must(t, err)
		check(t, string(value[:n]) == "retained", "source attribute lost")
	}
}
