package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// copyTree anchors every ancestor and every recursive operation to open
// descriptors. A leaf that changes between inspection and open is refused.
func (a *App) copyTree(src, dest string) error {
	source, err := openPathDir(src)
	if err != nil {
		return err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return err
	}
	parent, err := mkdirPathDirs(filepath.Dir(dest))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(dest)
	a.fsBefore("copy-create", filepath.Dir(dest), name)
	if err = mkdirAt(parent, name, 0700); err != nil {
		return err
	}
	made, err := statAt(parent, name, false)
	if err != nil {
		return err
	}
	a.fsBefore("copy-dest-descend", filepath.Dir(dest), name)
	target, err := openCopyDir(parent, name, made)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = a.copyDirFD(source, target, sourceInfo, src, dest, device(sourceInfo)); err != nil {
		return err
	}
	if err = verifyCopyLeaf(parent, name, target); err != nil {
		return err
	}
	// Root names may have moved while their descriptors remained safely pinned.
	// Such a copy cannot be accepted as a completed move.
	fresh, err := openPathDir(src)
	if err != nil {
		return err
	}
	defer fresh.Close()
	current, err := fresh.Stat()
	if err != nil {
		return err
	}
	if !sameIdentity(current, sourceInfo) {
		return fmt.Errorf("source root changed during copy")
	}
	return nil
}
func openCopyDir(parent *os.File, name string, want os.FileInfo) (*os.File, error) {
	f, err := openAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	actual, err := f.Stat()
	if err != nil || !actual.IsDir() || !sameIdentity(actual, want) {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("directory %s changed during copy", name)
	}
	return f, nil
}
func verifyCopyLeaf(parent *os.File, name string, opened *os.File) error {
	want, err := opened.Stat()
	if err != nil {
		return err
	}
	actual, err := statAt(parent, name, false)
	if err != nil {
		return err
	}
	if !sameIdentity(actual, want) {
		return fmt.Errorf("entry %s changed during copy", name)
	}
	return nil
}
func (a *App) copyDirFD(source, target *os.File, info os.FileInfo, sourcePath, targetPath string, dev uint64) error {
	entries, err := source.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == ".DS_Store" {
			continue
		}
		st, err := statAt(source, name, false)
		if err != nil {
			return err
		}
		from, to := filepath.Join(sourcePath, name), filepath.Join(targetPath, name)
		switch {
		case st.IsDir():
			if device(st) != dev {
				return fmt.Errorf("copy contains another filesystem at %s", from)
			}
			a.fsBefore("copy-descend", sourcePath, name)
			child, err := openCopyDir(source, name, st)
			if err != nil {
				return err
			}
			err = func() error {
				defer child.Close()
				a.fsBefore("copy-create", targetPath, name)
				if err := mkdirAt(target, name, 0700); err != nil {
					return err
				}
				made, err := statAt(target, name, false)
				if err != nil {
					return err
				}
				a.fsBefore("copy-dest-descend", targetPath, name)
				out, err := openCopyDir(target, name, made)
				if err != nil {
					return err
				}
				defer out.Close()
				if err = a.copyDirFD(child, out, st, from, to, dev); err != nil {
					return err
				}
				if err = verifyCopyLeaf(source, name, child); err != nil {
					return err
				}
				return verifyCopyLeaf(target, name, out)
			}()
			if err != nil {
				return err
			}
		case st.Mode()&os.ModeSymlink != 0:
			a.fsBefore("copy-link", sourcePath, name)
			pinned, err := pinSymlinkAt(source, name)
			if err != nil {
				return err
			}
			err = func() error {
				defer pinned.Close()
				got, err := pinned.Stat()
				if err != nil {
					return err
				}
				if !sameIdentity(got, st) {
					return fmt.Errorf("symlink %s changed during copy", from)
				}
				link, err := readlinkAt(source, name)
				if err != nil {
					return err
				}
				if err = verifyCopyLeaf(source, name, pinned); err != nil {
					return err
				}
				a.fsBefore("copy-create", targetPath, name)
				if err = symlinkAt(link, target, name); err != nil {
					return err
				}
				made, err := statAt(target, name, false)
				if err != nil {
					return err
				}
				a.fsBefore("copy-link-metadata", targetPath, name)
				current, err := statAt(target, name, false)
				if err != nil {
					return err
				}
				if !sameIdentity(current, made) {
					return fmt.Errorf("destination symlink %s changed during copy", to)
				}
				if err = copySymlinkMetadataAt(source, name, target, name, st, made); err != nil {
					return err
				}
				if err = verifyCopyLeaf(source, name, pinned); err != nil {
					return err
				}
				current, err = statAt(target, name, false)
				if err != nil {
					return err
				}
				if !sameIdentity(current, made) {
					return fmt.Errorf("destination symlink %s changed during copy", to)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		case st.Mode().IsRegular():
			a.fsBefore("copy-read", sourcePath, name)
			in, err := openAt(source, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
			if err != nil {
				return err
			}
			err = func() error {
				defer in.Close()
				opened, err := in.Stat()
				if err != nil {
					return err
				}
				if !opened.Mode().IsRegular() || !sameIdentity(opened, st) {
					return fmt.Errorf("file %s changed during copy", from)
				}
				a.fsBefore("copy-create", targetPath, name)
				out, err := openAt(target, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
				if err != nil {
					return err
				}
				defer out.Close()
				if _, err = io.Copy(out, in); err != nil {
					return err
				}
				a.fsBefore("copy-metadata", targetPath, name)
				if err = copyMetadataFD(in, out, st); err != nil {
					return err
				}
				if err = verifyCopyLeaf(source, name, in); err != nil {
					return err
				}
				return verifyCopyLeaf(target, name, out)
			}()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot copy special file %s", from)
		}
	}
	a.fsBefore("copy-dir-metadata", targetPath, ".")
	return copyMetadataFD(source, target, info)
}
