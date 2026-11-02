package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalCopyPreservesFileFlags(t *testing.T) {
	e := newTestEnv(t)
	src := filepath.Join(e.Root, "flags-source")
	removalWrite(t, filepath.Join(src, "file"), "content")
	for _, p := range []string{src, filepath.Join(src, "file")} {
		must(t, syscall.Chflags(p, 1))
	}
	dest := filepath.Join(e.Root, "flags-copy")
	must(t, e.A.copyTree(src, dest))
	for _, p := range []string{dest, filepath.Join(dest, "file")} {
		info, err := os.Stat(p)
		must(t, err)
		check(t, info.Sys().(*syscall.Stat_t).Flags&1 != 0, "flags lost at %s", p)
	}
}
