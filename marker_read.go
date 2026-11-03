package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func (a *App) readMarker(folder string) (*Marker, error) {
	return a.readMarkerPath(folder, filepath.Join(folder, markerName))
}
func (a *App) readMarkerPath(folder, markerPath string) (*Marker, error) {
	folder = a.expand(folder)
	for _, path := range ancestors(folder) {
		if info, err := a.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink in path (%s); mark the real directory", path)
		}
	}
	dir, err := openPathDir(folder)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return a.readMarkerAt(dir, folder, filepath.Base(markerPath))
}
func (a *App) readMarkerAt(parent *os.File, folder, name string) (*Marker, error) {
	info, err := a.StatAt(parent, name, false)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("marker is not a regular file")
	}

	file, err := openAt(parent, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("marker changed while opening")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	marker, err := a.parseMarker(content, folder, opened)
	if err != nil {
		return nil, err
	}
	return marker, nil
}
