package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameAtNeverReplacesDestination(t *testing.T) {
	for _, kind := range []string{"directory", "file", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			destination := filepath.Join(root, "destination")
			switch kind {
			case "directory":
				must(t, os.Mkdir(source, 0700))
				must(t, os.WriteFile(filepath.Join(source, "payload"), []byte("retained"), 0600))
				must(t, os.Mkdir(destination, 0700))
			case "file":
				must(t, os.WriteFile(source, []byte("source retained"), 0600))
				must(t, os.WriteFile(destination, []byte("destination retained"), 0600))
			case "dangling-symlink":
				must(t, os.Symlink("missing-source-target", source))
				must(t, os.Symlink("missing-destination-target", destination))
			}
			sourceBefore, err := os.Lstat(source)
			must(t, err)
			destinationBefore, err := os.Lstat(destination)
			must(t, err)
			parent, err := os.Open(root)
			must(t, err)
			defer parent.Close()
			err = renameAt(parent, "source", parent, "destination")
			check(t, err != nil, "rename replaced existing %s", kind)
			sourceAfter, err := os.Lstat(source)
			must(t, err)
			destinationAfter, err := os.Lstat(destination)
			must(t, err)
			check(t, os.SameFile(sourceBefore, sourceAfter), "failed rename replaced source")
			check(t, os.SameFile(destinationBefore, destinationAfter), "failed rename replaced destination")
		})
	}
}

func TestRenameAtExclusiveAcrossDirectories(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "from")
	destinationDir := filepath.Join(root, "to")
	must(t, os.Mkdir(sourceDir, 0700))
	must(t, os.Mkdir(destinationDir, 0700))
	source := filepath.Join(sourceDir, "source")
	must(t, os.Mkdir(source, 0700))
	must(t, os.WriteFile(filepath.Join(source, "payload"), []byte("retained"), 0600))
	before, err := os.Lstat(source)
	must(t, err)
	from, err := os.Open(sourceDir)
	must(t, err)
	defer from.Close()
	to, err := os.Open(destinationDir)
	must(t, err)
	defer to.Close()
	must(t, renameAt(from, "source", to, "destination"))
	_, err = os.Lstat(source)
	check(t, os.IsNotExist(err), "rename retained source entry: %v", err)
	destination := filepath.Join(destinationDir, "destination")
	after, err := os.Lstat(destination)
	must(t, err)
	check(t, os.SameFile(before, after), "rename changed directory identity")
	content, err := os.ReadFile(filepath.Join(destination, "payload"))
	must(t, err)
	check(t, string(content) == "retained", "rename changed payload: %q", content)
}
