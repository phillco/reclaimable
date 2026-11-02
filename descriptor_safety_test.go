package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Swap after the child descriptor was opened, at the original scandir boundary.
func descriptorSwapAtReadDir(t *testing.T, e *testEnv, op, child, outside string) *bool {
	t.Helper()
	swapped := false
	e.A.FSBefore = func(gotOp, parent, name string) {
		if swapped || gotOp != op || parent != child || name != "." {
			return
		}
		swapped = true
		must(t, os.Rename(child, filepath.Join(filepath.Dir(child), "parked")))
		must(t, os.Symlink(outside, child))
	}
	return &swapped
}
func TestRemovalChildSwapNeverFollowsSymlink(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "remove")
	child := filepath.Join(root, "child")
	must(t, os.MkdirAll(child, 0755))
	outside := filepath.Join(e.Root, "outside")
	sentinel := filepath.Join(outside, "sentinel")
	removalWrite(t, sentinel, "keep")
	swapped := descriptorSwapAtReadDir(t, e, "remove-read-dir", child, outside)
	left, err := e.A.rmtreeSameDev(root)
	must(t, err)
	b, err := os.ReadFile(sentinel)
	must(t, err)
	info, err := os.Lstat(child)
	must(t, err)
	check(t, *swapped && string(b) == "keep" && len(left) > 0 && info.Mode()&os.ModeSymlink != 0, "left=%v swapped=%v", left, *swapped)
}
func TestHasherChildSwapNeverReadsSymlinkTarget(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "hash")
	child := filepath.Join(root, "child")
	must(t, os.MkdirAll(child, 0755))
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "sentinel"), "private")
	swapped := descriptorSwapAtReadDir(t, e, "hash-read-dir", child, outside)
	inventory, _ := e.A.fileHashes(root)
	_, leaked := inventory["child/sentinel"]
	check(t, *swapped && !leaked, "inventory escaped: %v", inventory)
}
func TestCopyChildSwapNeverCopiesSymlinkTarget(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, map[string][]byte{"child/inside": []byte("inside")}, nil)
	outside := filepath.Join(e.Root, "outside")
	sentinel := filepath.Join(outside, "sentinel")
	removalWrite(t, sentinel, "private")
	hashes, err := e.A.FileHashes(root)
	must(t, err)
	swapped := descriptorSwapAtReadDir(t, e, "copy-read-dir", filepath.Join(root, "child"), outside)
	archive := filepath.Join(e.Root, "archive")
	ok, detail := e.A.moveAndVerify(root, archive, nil, hashes)
	b, err := os.ReadFile(sentinel)
	must(t, err)
	check(t, *swapped && !ok && string(b) == "private", "%v %s swapped=%v", ok, detail, *swapped)
	must(t, filepath.WalkDir(archive, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		check(t, entry.Name() != "sentinel", "outside sentinel copied to %s", path)
		return nil
	}))
}
func TestHasherFileSwapNeverReadsSymlinkTarget(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, map[string][]byte{"payload": []byte("inside")}, nil)
	outside := filepath.Join(e.Root, "sentinel")
	removalWrite(t, outside, "private")
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if swapped || op != "hash-entry" || parent != root || name != "payload" {
			return
		}
		swapped = true
		must(t, os.Remove(filepath.Join(root, "payload")))
		must(t, os.Symlink(outside, filepath.Join(root, "payload")))
	}
	inventory, _ := e.A.fileHashes(root)
	privateHash := fmt.Sprintf("%x", sha256.Sum256([]byte("private")))
	check(t, swapped, "race hook did not run")
	for _, digest := range inventory {
		check(t, digest != privateHash, "outside file bytes were hashed")
	}
}
func TestHasherRefusesSpecialFiles(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, nil, nil)
	must(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0600))
	_, err := e.A.fileHashes(root)
	check(t, err != nil, "hasher accepted FIFO")
}
func TestMarkerSwapNeverBypassesNestedHold(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "outer", 30*day, nil, nil)
	child := e.make(t, "outer/child", 30*day, nil, map[string]any{"holds": []map[string]any{{"job": "reader"}}})
	outside := e.make(t, "outside", 30*day, nil, nil)
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if swapped || op != "marker-open" || parent != child || name != markerName {
			return
		}
		swapped = true
		must(t, os.Rename(filepath.Join(child, markerName), filepath.Join(child, "held-marker")))
		must(t, os.Symlink(filepath.Join(outside, markerName), filepath.Join(child, markerName)))
	}
	verdict := e.A.evaluate(root, e.Cfg, e.Reg, true)
	check(t, swapped && !verdict.Safe, "%s swapped=%v", debugVerdict(verdict), swapped)
}
func TestCopyPinsDestinationIdentity(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, map[string][]byte{"payload": []byte("new")}, nil)
	archive := filepath.Join(e.Root, "archive")
	_, dest := e.A.moveDestination(archive, root)
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if swapped || op != "copy-create" || parent != dest || name != "payload" {
			return
		}
		swapped = true
		must(t, os.Rename(dest, filepath.Join(filepath.Dir(dest), "parked")))
		must(t, os.Mkdir(dest, 0755))
		removalWrite(t, filepath.Join(dest, "sentinel"), "keep")
	}
	ok, detail := e.A.moveAndVerify(root, archive, nil, nil)
	b, err := os.ReadFile(filepath.Join(dest, "sentinel"))
	must(t, err)
	check(t, swapped && !ok && exists(root) && string(b) == "keep" && !exists(filepath.Join(dest, "payload")), "%v %s swapped=%v", ok, detail, swapped)
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
func TestFileModifiedDuringHashFailsClosed(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 0, map[string][]byte{"payload": []byte("before")}, nil)
	changed := false
	e.A.FSBefore = func(op, parent, name string) {
		if changed || op != "hash-read" || parent != root || name != "payload" {
			return
		}
		changed = true
		must(t, os.WriteFile(filepath.Join(root, "payload"), []byte("after"), 0644))
	}
	_, err := e.A.fileHashes(root)
	check(t, changed && err != nil && strings.Contains(err.Error(), "changed"), "changed=%v error=%v", changed, err)
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
func TestFinalRenameDoesNotFollowReplacedParent(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "parent/source", 30*day, nil, nil)
	verdict := e.A.evaluate(root, e.Cfg, e.Reg, true)
	outside := filepath.Join(e.Root, "outside")
	sentinel := filepath.Join(outside, "source/sentinel")
	removalWrite(t, sentinel, "keep")
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if swapped || op != "remove-rename" || parent != filepath.Dir(root) || name != filepath.Base(root) {
			return
		}
		swapped = true
		must(t, os.Rename(filepath.Dir(root), filepath.Join(filepath.Dir(filepath.Dir(root)), "parked-parent")))
		must(t, os.Symlink(outside, filepath.Dir(root)))
	}
	ok, detail := e.A.removeFolder(verdict, true, e.Cfg, e.Reg)
	b, err := os.ReadFile(sentinel)
	must(t, err)
	check(t, swapped && !ok && string(b) == "keep", "%v %s swapped=%v", ok, detail, swapped)
}
func TestDiscoveryNeverFollowsSwappedChild(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "discover")
	child := filepath.Join(root, "child")
	must(t, os.MkdirAll(child, 0755))
	outside := e.make(t, "outside", 0, nil, nil)
	swapped := descriptorSwapAtReadDir(t, e, "scan-read-dir", child, outside)
	found, complete := e.A.scan([]string{root}, e.Cfg, 120)
	check(t, *swapped && !complete && len(found) == 0, "swapped=%v complete=%v found=%v", *swapped, complete, found)
}
func TestReplacedFolderAfterEvaluationIsKept(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 30*day, nil, nil)
	verdict := e.A.evaluate(root, e.Cfg, e.Reg, true)
	marker, err := os.ReadFile(filepath.Join(root, markerName))
	must(t, err)
	stamp, err := os.Stat(filepath.Join(root, markerName))
	must(t, err)
	must(t, os.Rename(root, filepath.Join(filepath.Dir(root), "parked-source")))
	must(t, os.Mkdir(root, 0755))
	must(t, os.WriteFile(filepath.Join(root, markerName), marker, 0644))
	must(t, os.Chtimes(filepath.Join(root, markerName), accessTime(stamp), stamp.ModTime()))
	sentinel := filepath.Join(root, "replacement")
	removalWrite(t, sentinel, "keep")
	ok, detail := e.A.removeFolder(verdict, true, e.Cfg, e.Reg)
	b, err := os.ReadFile(sentinel)
	must(t, err)
	check(t, !ok && strings.Contains(detail, "replaced") && string(b) == "keep", "%v %s", ok, detail)
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
