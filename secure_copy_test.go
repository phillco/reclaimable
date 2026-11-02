package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecureCopyRejectsSwappedSourceEntries(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			src := filepath.Join(e.Root, "source")
			dest := filepath.Join(e.Root, "copy")
			victim := filepath.Join(e.Root, "outside")
			removalWrite(t, filepath.Join(src, "sub/file"), "source")
			removalWrite(t, filepath.Join(victim, "precious"), "outside bytes")
			must(t, os.Symlink("sub/file", filepath.Join(src, "link")))
			op, name := "copy-read", "file"
			parent := filepath.Join(src, "sub")
			if kind == "directory" {
				op, name, parent = "copy-descend", "sub", src
			}
			if kind == "symlink" {
				op, name, parent = "copy-link", "link", src
			}
			fired := false
			e.A.FSBefore = func(gotOp, gotParent, gotName string) {
				if fired || gotOp != op || gotParent != parent || gotName != name {
					return
				}
				fired = true
				path := filepath.Join(parent, name)
				must(t, os.Rename(path, filepath.Join(e.Root, "saved-source")))
				must(t, os.Symlink(victim, path))
			}
			err := e.A.copyTree(src, dest)
			check(t, fired && err != nil, "copy accepted swapped %s: %v", kind, err)
			b, err := os.ReadFile(filepath.Join(victim, "precious"))
			must(t, err)
			check(t, string(b) == "outside bytes", "outside bytes changed")
		})
	}
}
func TestSecureCopyRejectsSwappedDestinationEntries(t *testing.T) {
	for _, kind := range []string{"directory", "file-before-create", "file-before-metadata", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			src := filepath.Join(e.Root, "source")
			dest := filepath.Join(e.Root, "copy")
			victim := filepath.Join(e.Root, "outside")
			removalWrite(t, filepath.Join(src, "sub/file"), "source")
			precious := filepath.Join(victim, "precious")
			removalWrite(t, precious, "outside bytes")
			must(t, os.Chmod(precious, 0600))
			stamp := time.Unix(1500000000, 123456789)
			must(t, os.Chtimes(precious, stamp, stamp))
			before, err := os.Stat(precious)
			must(t, err)
			must(t, os.Symlink("sub/file", filepath.Join(src, "link")))
			fired := false
			e.A.FSBefore = func(op, parent, name string) {
				if fired {
					return
				}
				match := false
				switch kind {
				case "directory":
					match = op == "copy-dest-descend" && parent == dest && name == "sub"
				case "file-before-create":
					match = op == "copy-create" && parent == filepath.Join(dest, "sub") && name == "file"
				case "file-before-metadata":
					match = op == "copy-metadata" && parent == filepath.Join(dest, "sub") && name == "file"
				case "symlink":
					match = op == "copy-link-metadata" && parent == dest && name == "link"
				}
				if !match {
					return
				}
				fired = true
				path := filepath.Join(parent, name)
				if kind != "file-before-create" {
					must(t, os.Rename(path, filepath.Join(e.Root, "saved-destination")))
				}
				target := precious
				if kind == "directory" {
					target = victim
				}
				must(t, os.Symlink(target, path))
			}
			err = e.A.copyTree(src, dest)
			check(t, fired && err != nil, "copy accepted destination swap %s: %v", kind, err)
			after, err := os.Stat(precious)
			must(t, err)
			check(t, after.Mode() == before.Mode() && after.ModTime().Equal(before.ModTime()), "outside metadata changed")
			b, err := os.ReadFile(precious)
			must(t, err)
			check(t, string(b) == "outside bytes", "outside bytes changed")
		})
	}
}
func TestSecureCopyPinsRenamedAncestors(t *testing.T) {
	for _, side := range []string{"source", "destination"} {
		t.Run(side, func(t *testing.T) {
			e := newTestEnv(t)
			src := filepath.Join(e.Root, "source")
			dest := filepath.Join(e.Root, "copy")
			victim := filepath.Join(e.Root, "outside")
			removalWrite(t, filepath.Join(src, "sub/file"), "source")
			removalWrite(t, filepath.Join(victim, "precious"), "outside bytes")
			fired := false
			e.A.FSBefore = func(op, parent, name string) {
				if fired {
					return
				}
				path := ""
				if side == "source" && op == "copy-read" && parent == filepath.Join(src, "sub") && name == "file" {
					path = src
				}
				if side == "destination" && op == "copy-dir-metadata" && parent == dest {
					path = dest
				}
				if path == "" {
					return
				}
				fired = true
				must(t, os.Rename(path, filepath.Join(e.Root, "saved-ancestor")))
				must(t, os.Symlink(victim, path))
			}
			err := e.A.copyTree(src, dest)
			check(t, fired && err != nil, "copy accepted renamed %s ancestor: %v", side, err)
			entries, err := os.ReadDir(victim)
			must(t, err)
			check(t, len(entries) == 1 && entries[0].Name() == "precious", "outside tree changed")
			b, err := os.ReadFile(filepath.Join(victim, "precious"))
			must(t, err)
			check(t, string(b) == "outside bytes", "outside bytes changed")
		})
	}
}
func TestMoveKeepsSourceWhenCopyEntrySwapped(t *testing.T) {
	e := newTestEnv(t)
	f, _ := makeMovable(t, e, "copy-race")
	victim := filepath.Join(e.Root, "outside-file")
	removalWrite(t, victim, "outside bytes")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe, "unsafe fixture: %s", v.Reason)
	fired := false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "copy-read" || parent != f || name != "a.txt" {
			return
		}
		fired = true
		must(t, os.Rename(filepath.Join(parent, name), filepath.Join(e.Root, "saved-file")))
		must(t, os.Symlink(victim, filepath.Join(parent, name)))
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, fired && !ok && exists(f), "source was not kept: %v %s", ok, detail)
	b, err := os.ReadFile(victim)
	must(t, err)
	check(t, string(b) == "outside bytes", "outside bytes changed")
}
