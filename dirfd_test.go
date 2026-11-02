package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDirFDOperations(t *testing.T) {
	root := t.TempDir()
	parent, err := os.Open(root)
	must(t, err)
	defer parent.Close()
	must(t, mkdirAt(parent, "directory", 0750))
	folder, err := openAt(parent, "directory", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	must(t, err)
	defer folder.Close()
	file, err := openAt(folder, "file", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0640)
	must(t, err)
	_, err = file.WriteString("retained")
	must(t, err)
	must(t, file.Close())
	relative, err := statAt(folder, "file", false)
	must(t, err)
	ordinary, err := os.Lstat(filepath.Join(root, "directory/file"))
	must(t, err)
	check(t, relative.Name() == "file" && relative.Size() == ordinary.Size() && relative.Mode() == ordinary.Mode() && relative.ModTime().Equal(ordinary.ModTime()) && device(relative) == device(ordinary) && inode(relative) == inode(ordinary), "relative stat differs: %+v ordinary %+v", relative, ordinary)
	opened, err := openAt(folder, "file", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	must(t, err)
	content, err := io.ReadAll(opened)
	must(t, err)
	must(t, opened.Close())
	check(t, string(content) == "retained", "read %q", content)
	must(t, symlinkAt("file", folder, "link"))
	target, err := readlinkAt(folder, "link")
	must(t, err)
	check(t, target == "file", "target %q", target)
	link, err := statAt(folder, "link", false)
	must(t, err)
	check(t, link.Mode()&os.ModeSymlink != 0, "stat followed link")
	followed, err := statAt(folder, "link", true)
	must(t, err)
	check(t, inode(followed) == inode(ordinary), "follow stat wrong target")
	blocked, err := openAt(folder, "link", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if blocked != nil {
		blocked.Close()
	}
	check(t, err != nil, "nofollow open followed symlink")
	must(t, renameAt(folder, "file", folder, "renamed"))
	_, err = statAt(folder, "file", false)
	check(t, errors.Is(err, os.ErrNotExist), "rename kept old child: %v", err)
	must(t, unlinkAt(folder, "link", false))
	must(t, unlinkAt(folder, "renamed", false))
	must(t, unlinkAt(parent, "directory", true))
	_, err = statAt(parent, "directory", false)
	check(t, errors.Is(err, os.ErrNotExist), "directory not removed: %v", err)
}
func TestDirFDOperationsStayInOpenedDirectoryAfterPathSwap(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	victim := filepath.Join(root, "victim")
	must(t, os.Mkdir(original, 0755))
	must(t, os.Mkdir(victim, 0755))
	must(t, os.WriteFile(filepath.Join(original, "child"), []byte("disposable"), 0644))
	must(t, os.WriteFile(filepath.Join(victim, "child"), []byte("precious"), 0644))
	parent, err := os.Open(original)
	must(t, err)
	defer parent.Close()
	must(t, os.Rename(original, filepath.Join(root, "moved")))
	must(t, os.Symlink(victim, original))
	file, err := openAt(parent, "child", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	must(t, err)
	b, err := io.ReadAll(file)
	must(t, err)
	must(t, file.Close())
	check(t, string(b) == "disposable", "opened swapped path: %q", b)
	must(t, unlinkAt(parent, "child", false))
	must(t, mkdirAt(parent, "new-directory", 0755))
	must(t, symlinkAt("target", parent, "new-link"))
	must(t, renameAt(parent, "new-link", parent, "renamed-link"))
	b, err = os.ReadFile(filepath.Join(victim, "child"))
	must(t, err)
	check(t, string(b) == "precious", "victim changed: %q", b)
	check(t, !exists(filepath.Join(victim, "new-directory")) && !exists(filepath.Join(victim, "new-link")), "mutation escaped pinned directory")
	must(t, unlinkAt(parent, "renamed-link", false))
	must(t, unlinkAt(parent, "new-directory", true))
}
func TestDirFDLeafNamesRefuseTraversal(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	must(t, err)
	defer parent.Close()
	for _, name := range []string{"", "..", "../outside", "nested/child", "/absolute", "nul\x00child"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			f, err := openAt(parent, name, os.O_RDONLY, 0)
			if f != nil {
				f.Close()
			}
			check(t, err != nil, "open accepted %q", name)
			_, err = statAt(parent, name, false)
			check(t, err != nil, "stat accepted %q", name)
			check(t, unlinkAt(parent, name, false) != nil, "unlink accepted %q", name)
			check(t, mkdirAt(parent, name, 0700) != nil, "mkdir accepted %q", name)
			_, err = readlinkAt(parent, name)
			check(t, err != nil, "readlink accepted %q", name)
			check(t, symlinkAt("target", parent, name) != nil, "symlink accepted %q", name)
			check(t, renameAt(parent, name, parent, "safe") != nil, "rename source accepted %q", name)
			check(t, renameAt(parent, "safe", parent, name) != nil, "rename destination accepted %q", name)
		})
	}
}
func TestDirFDReadlinkLongTarget(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	must(t, err)
	defer parent.Close()
	target := strings.Repeat("part/", 100) + "end"
	must(t, symlinkAt(target, parent, "long-link"))
	got, err := readlinkAt(parent, "long-link")
	must(t, err)
	check(t, got == target, "long target truncated")
}

func TestDirFDSetTimesAnchorsOpenFile(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	victim := filepath.Join(root, "victim")
	must(t, os.WriteFile(original, []byte("first"), 0644))
	must(t, os.WriteFile(victim, []byte("precious"), 0644))
	parent, err := os.Open(root)
	must(t, err)
	defer parent.Close()
	file, err := openAt(parent, "original", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	must(t, err)
	defer file.Close()
	must(t, os.Rename(original, filepath.Join(root, "moved")))
	must(t, os.Symlink(victim, original))
	before, err := os.Stat(victim)
	must(t, err)
	at := time.Unix(1600000000, 123456789)
	mt := time.Unix(1600000100, 987654321)
	must(t, fdSetTimes(file, at, mt))
	got, err := file.Stat()
	must(t, err)
	after, err := os.Stat(victim)
	must(t, err)
	check(t, accessTime(got).Equal(at) && got.ModTime().Equal(mt), "fd times at=%v mt=%v", accessTime(got), got.ModTime())
	check(t, after.ModTime().Equal(before.ModTime()), "metadata followed replacement symlink")
}
func TestDirFDSetSymlinkTimesDoesNotFollowTarget(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	must(t, os.WriteFile(victim, []byte("precious"), 0644))
	parent, err := os.Open(root)
	must(t, err)
	defer parent.Close()
	must(t, symlinkAt("victim", parent, "link"))
	file, err := pinSymlinkAt(parent, "link")
	must(t, err)
	defer file.Close()
	before, err := os.Stat(victim)
	must(t, err)
	at := time.Unix(1600000200, 123456789)
	mt := time.Unix(1600000300, 987654321)
	must(t, fdSetTimes(file, at, mt))
	got, err := statAt(parent, "link", false)
	must(t, err)
	after, err := os.Stat(victim)
	must(t, err)
	check(t, got.Mode()&os.ModeSymlink != 0 && accessTime(got).Equal(at) && got.ModTime().Equal(mt), "link times at=%v mt=%v mode=%v", accessTime(got), got.ModTime(), got.Mode())
	check(t, after.ModTime().Equal(before.ModTime()), "symlink timestamps modified target")
}

func TestDirFDPinSymlinkRejectsRegularFile(t *testing.T) {
	root := t.TempDir()
	must(t, os.WriteFile(filepath.Join(root, "regular"), []byte("precious"), 0644))
	parent, err := os.Open(root)
	must(t, err)
	defer parent.Close()
	file, err := pinSymlinkAt(parent, "regular")
	if file != nil {
		file.Close()
	}
	check(t, err != nil, "non-symlink entry accepted as pinned symlink")
}
