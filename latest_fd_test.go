package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMarkerSymlinkSwapBeforeReadIsRefused(t *testing.T) {
	e := newTestEnv(t)
	folder := e.make(t, "marker-race", 30*day, nil, nil)
	outside := filepath.Join(e.Root, "outside-marker")
	removalWrite(t, outside, `{"owner":"outside-owner","regenerate":"preserve outside payload"}`)
	before, err := os.Stat(outside)
	must(t, err)
	fired := false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "marker-open" || parent != folder || name != markerName {
			return
		}
		fired = true
		must(t, os.Rename(filepath.Join(folder, name), filepath.Join(e.Root, "saved-marker")))
		must(t, os.Symlink(outside, filepath.Join(folder, name)))
	}
	marker, err := e.A.readMarker(folder)
	check(t, fired && err != nil && marker == nil, "marker swap accepted: marker=%+v err=%v", marker, err)
	after, err := os.Stat(outside)
	must(t, err)
	content, err := os.ReadFile(outside)
	must(t, err)
	check(t, string(content) == `{"owner":"outside-owner","regenerate":"preserve outside payload"}` && after.ModTime().Equal(before.ModTime()), "outside marker changed")
}

func TestFinalRenamePinsParentAfterPathSwap(t *testing.T) {
	e := newTestEnv(t)
	folder := e.make(t, "rename-race", 30*day, nil, nil)
	parent := filepath.Dir(folder)
	victim := filepath.Join(e.Root, "outside-parent")
	precious := filepath.Join(victim, filepath.Base(folder), "precious")
	removalWrite(t, precious, "outside bytes")
	stamp := time.Unix(1500000000, 123456789)
	must(t, os.Chtimes(precious, stamp, stamp))
	must(t, os.Chmod(precious, 0600))
	before, err := os.Stat(precious)
	must(t, err)
	verdict := e.A.evaluate(folder, e.Cfg, e.Reg, true)
	check(t, verdict.Safe && verdict.Expired, "unsafe fixture: %s", debugVerdict(verdict))
	fired := false
	e.A.FSBefore = func(op, logical, name string) {
		if fired || op != "remove-rename" || logical != parent || name != filepath.Base(folder) {
			return
		}
		fired = true
		must(t, os.Rename(parent, filepath.Join(e.Root, "saved-parent")))
		must(t, os.Symlink(victim, parent))
	}
	e.A.removeFolder(verdict, true, e.Cfg, e.Reg)
	after, err := os.Stat(precious)
	must(t, err)
	content, err := os.ReadFile(precious)
	must(t, err)
	check(t, fired && string(content) == "outside bytes" && after.Mode() == before.Mode() && after.ModTime().Equal(before.ModTime()), "rename escaped pinned parent")
	entries, err := os.ReadDir(victim)
	must(t, err)
	check(t, len(entries) == 1 && entries[0].Name() == filepath.Base(folder), "quarantine operation escaped to outside parent: %v", entries)
}

func TestDestinationRootSwapBeforeVerificationKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	folder, destRoot := makeMovable(t, e, "destination-race")
	_, destination := e.A.moveDestination(destRoot, folder)
	sameContent := filepath.Join(e.Root, "outside-matching-copy")
	must(t, e.A.copyTree(folder, sameContent))
	verdict := e.A.evaluate(folder, e.Cfg, e.Reg, true)
	check(t, verdict.Safe && verdict.Action == "move", "unsafe fixture: %s", debugVerdict(verdict))
	fired := false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "verify-copy-root" || filepath.Join(parent, name) != destination {
			return
		}
		fired = true
		must(t, os.Rename(destination, filepath.Join(e.Root, "saved-destination")))
		must(t, os.Symlink(sameContent, destination))
	}
	ok, detail := e.A.removeFolder(verdict, true, e.Cfg, e.Reg)
	check(t, fired && !ok && exists(folder), "source removed despite destination swap: %v %s", ok, detail)
	source, err := os.ReadFile(filepath.Join(folder, "a.txt"))
	must(t, err)
	outside, err := os.ReadFile(filepath.Join(sameContent, "a.txt"))
	must(t, err)
	check(t, string(source) == "hello" && string(outside) == "hello", "payload changed")
	info, err := os.Lstat(destination)
	must(t, err)
	check(t, info.Mode()&os.ModeSymlink != 0, "verification altered replacement entry")
}

func TestMarkerWriteAtFinalStatIsRefused(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "late-marker", 30*day, nil, nil)
	real := e.A.StatAt
	seen := 0
	e.A.StatAt = func(parent *os.File, name string, follow bool) (os.FileInfo, error) {
		if name == markerName {
			seen++
			if seen == 2 {
				must(t, os.WriteFile(filepath.Join(f, name), []byte(`{"owner":"test","regenerate":"rerun","holds":[{"job":"reader"}]}`), 0600))
			}
		}
		return real(parent, name, follow)
	}
	_, err := e.A.readMarker(f)
	check(t, err != nil && seen == 2, "late marker write accepted")
}
func TestHashWriteAtFinalStatIsRefused(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "late-hash", 30*day, map[string][]byte{"payload": []byte("before")}, nil)
	real := e.A.StatAt
	seen := 0
	e.A.StatAt = func(parent *os.File, name string, follow bool) (os.FileInfo, error) {
		if name == "payload" {
			seen++
			if seen == 2 {
				must(t, os.WriteFile(filepath.Join(f, name), []byte("after"), 0600))
			}
		}
		return real(parent, name, follow)
	}
	_, err := e.A.fileHashes(f)
	check(t, err != nil && seen == 2, "late hash write accepted")
}

func TestHashRejectsFileAddedAfterEnumeration(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "added-during-hash", 30*day, map[string][]byte{"payload": []byte("before")}, nil)
	added := false
	e.A.FSBefore = func(op, parent, name string) {
		if op == "hash-read" && parent == f && !added {
			added = true
			must(t, os.WriteFile(filepath.Join(f, "new-precious"), []byte("keep"), 0600))
		}
	}
	_, err := e.A.fileHashes(f)
	check(t, added && err != nil, "hash omitted newly created file")
	b, err := os.ReadFile(filepath.Join(f, "new-precious"))
	must(t, err)
	check(t, string(b) == "keep", "new file changed")
}
