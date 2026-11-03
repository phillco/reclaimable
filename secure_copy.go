package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// copyTree anchors every ancestor and every recursive operation to open
// descriptors, without following symlink ancestors or directory entries.
func (a *App) copyTree(src, dest string) error {
	target, err := a.copyTreePinned(src, dest)
	if target != nil {
		target.Close()
	}
	return err
}
func (a *App) copyTreePinned(src, dest string) (target *os.File, err error) {
	source, err := openPathDir(src)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, err
	}
	parent, err := mkdirPathDirs(filepath.Dir(dest))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(dest)

	if err = mkdirAt(parent, name, 0700); err != nil {
		return nil, err
	}
	target, err = openCopyDir(parent, name)
	if err != nil {
		return nil, err
	}
	openedTarget := target
	defer func() {
		if err != nil {
			openedTarget.Close()
		}
	}()
	if err = a.copyDirFD(source, target, sourceInfo, src, dest, device(sourceInfo)); err != nil {
		return nil, err
	}
	return target, nil
}
func openCopyDir(parent *os.File, name string) (*os.File, error) {
	f, err := openAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (a *App) copyDirFD(source, target *os.File, info os.FileInfo, sourcePath, targetPath string, dev uint64) error {
	if err := refuseExtendedDataFD(source); err != nil {
		return err
	}

	entries, err := source.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		st, err := statAt(source, name, false)
		if err != nil {
			return err
		}
		if name == ".DS_Store" && !st.IsDir() {
			continue
		}
		from, to := filepath.Join(sourcePath, name), filepath.Join(targetPath, name)
		switch {
		case st.IsDir():
			if device(st) != dev {
				return fmt.Errorf("copy contains another filesystem at %s", from)
			}

			child, err := openCopyDir(source, name)
			if err != nil {
				return err
			}
			err = func() error {
				defer child.Close()

				if err := mkdirAt(target, name, 0700); err != nil {
					return err
				}
				out, err := openCopyDir(target, name)
				if err != nil {
					return err
				}
				defer out.Close()
				return a.copyDirFD(child, out, st, from, to, dev)
			}()
			if err != nil {
				return err
			}
		case st.Mode()&os.ModeSymlink != 0:

			pinned, err := pinSymlinkAt(source, name)
			if err != nil {
				return err
			}
			err = func() error {
				defer pinned.Close()
				if err := refuseSymlinkExtendedDataAt(source, name, pinned); err != nil {
					return err
				}
				link, err := readlinkAt(source, name)
				if err != nil {
					return err
				}

				if err = symlinkAt(link, target, name); err != nil {
					return err
				}
				made, err := statAt(target, name, false)
				if err != nil {
					return err
				}
				if err = copySymlinkMetadataAt(source, name, target, name, st, made); err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return err
			}
		case st.Mode().IsRegular():

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
				if !opened.Mode().IsRegular() {
					return fmt.Errorf("file %s changed during copy", from)
				}
				if err := refuseExtendedDataFD(in); err != nil {
					return err
				}

				out, err := openAt(target, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
				if err != nil {
					return err
				}
				defer out.Close()
				if _, err = io.Copy(out, in); err != nil {
					return err
				}

				if err = copyMetadataFD(in, out, st); err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot copy special file %s", from)
		}
	}

	return copyMetadataFD(source, target, info)
}
