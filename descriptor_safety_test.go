package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestHasherRefusesSpecialFiles(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, nil, nil)
	must(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0600))
	_, err := e.A.fileHashes(root)
	check(t, err != nil, "hasher accepted FIFO")
}
func TestCopyRefusesSymlinkDestinationAncestor(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, nil, nil)
	outside := filepath.Join(e.Root, "outside")
	must(t, os.Mkdir(outside, 0755))
	archive := filepath.Join(e.Root, "archive")
	must(t, os.Symlink(outside, archive))
	ok, detail := e.A.moveAndVerify(root, archive, nil, nil)
	entries, err := os.ReadDir(outside)
	must(t, err)
	check(t, !ok && exists(root) && len(entries) == 0, "%v %s entries=%v", ok, detail, entries)
}
func TestCopyPreservesMarkerAgeAndExecutableMode(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 30*day, map[string][]byte{"tool": []byte("executable")}, nil)
	must(t, os.Chmod(filepath.Join(root, "tool"), 0755))
	archive := filepath.Join(e.Root, "archive")
	ok, detail := e.A.moveAndVerify(root, archive, nil, nil)
	check(t, ok, "%s", detail)
	_, dest := e.A.moveDestination(archive, root)
	mode, err := os.Stat(filepath.Join(dest, "tool"))
	must(t, err)
	copied, err := os.Stat(filepath.Join(dest, markerName))
	must(t, err)
	original, err := os.Stat(filepath.Join(root, markerName))
	must(t, err)
	check(t, mode.Mode().Perm() == 0755 && copied.ModTime().Equal(original.ModTime()), "mode=%v copied=%v original=%v", mode.Mode(), copied.ModTime(), original.ModTime())
}
func TestResourceForkKeepsSourceDuringMove(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("resource forks are macOS data")
	}
	for _, target := range []string{"payload", ".", "link"} {
		t.Run(target, func(t *testing.T) {
			e := newTestEnv(t)
			root := e.make(t, "source", 0, map[string][]byte{"payload": []byte("data")}, nil)
			must(t, os.Symlink("payload", filepath.Join(root, "link")))
			attr := "user.fixture"
			if target == "payload" {
				attr = "com.apple.ResourceFork"
			}
			cmd := exec.Command("/usr/bin/xattr", "-s", "-w", attr, "keep-fork", filepath.Join(root, target))
			output, err := cmd.CombinedOutput()
			check(t, err == nil, "fixture xattr setup: %v %s", err, output)
			ok, detail := e.A.moveAndVerify(root, filepath.Join(e.Root, "archive"), nil, nil)
			b, err := os.ReadFile(filepath.Join(root, "payload"))
			must(t, err)
			check(t, !ok && strings.Contains(detail, "extended data") && string(b) == "data", "%v %s", ok, detail)
		})
	}
}
