package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirFDSymlinkFlagsDoNotFollowTarget(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	must(t, os.WriteFile(victim, []byte("precious"), 0644))
	parent, err := os.Open(root)
	must(t, err)
	defer parent.Close()
	must(t, symlinkAt("victim", parent, "link"))
	link, err := pinSymlinkAt(parent, "link")
	must(t, err)
	defer link.Close()
	must(t, syscall.Fchflags(int(link.Fd()), 1))
	got, err := statAt(parent, "link", false)
	must(t, err)
	target, err := os.Stat(victim)
	must(t, err)
	check(t, got.Sys().(*syscall.Stat_t).Flags&1 != 0, "symlink flags not set")
	check(t, target.Sys().(*syscall.Stat_t).Flags&1 == 0, "symlink flag update followed target")
}
