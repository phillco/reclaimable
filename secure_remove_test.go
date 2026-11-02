package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDescriptorRemovalPinsSwappedAncestor(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "tree")
	removalWrite(t, filepath.Join(root, "sub/disposable"), "delete")
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "sub/precious"), "keep")
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if op == "remove-open" && name == "sub" && !swapped {
			swapped = true
			must(t, os.Rename(root, root+"-away"))
			must(t, os.Symlink(outside, root))
		}
	}
	_, err := e.A.rmtreeSameDev(root)
	must(t, err)
	b, err := os.ReadFile(filepath.Join(outside, "sub/precious"))
	must(t, err)
	check(t, swapped && string(b) == "keep", "outside sentinel changed")
}
func TestDescriptorHashRejectsSwappedChild(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "hash-source")
	removalWrite(t, filepath.Join(root, "sub/disposable"), "source")
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "precious"), "keep")
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if op == "hash-descend" && name == "sub" && !swapped {
			swapped = true
			must(t, os.Rename(filepath.Join(root, "sub"), root+"-saved"))
			must(t, os.Symlink(outside, filepath.Join(root, "sub")))
		}
	}
	_, err := e.A.fileHashes(root)
	check(t, err != nil && swapped, "hash followed swapped child")
	b, err := os.ReadFile(filepath.Join(outside, "precious"))
	must(t, err)
	check(t, string(b) == "keep", "outside sentinel changed")
}
func TestDescriptorHashPinsSwappedAncestor(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "hash-source")
	removalWrite(t, filepath.Join(root, "sub/disposable"), "source")
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "sub/precious"), "keep")
	swapped := false
	e.A.FSBefore = func(op, parent, name string) {
		if op == "hash-descend" && name == "sub" && !swapped {
			swapped = true
			must(t, os.Rename(root, root+"-away"))
			must(t, os.Symlink(outside, root))
		}
	}
	hashes, err := e.A.fileHashes(root)
	must(t, err)
	check(t, swapped && hashes["sub/disposable"] != "" && hashes["sub/precious"] == "", "hash escaped pinned tree: %v", hashes)
}
