package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const defaultRootWorker = "--internal-default-root-probe"

type defaultRootResult struct {
	Names   []string `json:"names,omitempty"`
	Include bool     `json:"include,omitempty"`
}

// Re-exec the same binary so a stalled filesystem or macOS consent request
// cannot strand a goroutine, descriptor, or lock in the sweep process. init also
// makes the worker available in test binaries without running the test suite.
func init() {
	if len(os.Args) != 4 || os.Args[1] != defaultRootWorker {
		return
	}
	result, err := probeDefaultRoot(os.Args[2], os.Args[3])
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func defaultRootCommand(mode, path string) ([]string, error) {
	executable, err := os.Executable()
	return []string{executable, defaultRootWorker, mode, path}, err
}

func probeDefaultRoot(mode, path string) (defaultRootResult, error) {
	result := defaultRootResult{}
	if mode == "list" {
		entries, err := os.ReadDir(path)
		for _, entry := range entries {
			result.Names = append(result.Names, entry.Name())
		}
		return result, err
	}
	if mode != "probe" {
		return result, fmt.Errorf("unknown root probe mode %q", mode)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return result, err
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return result, err
	}
	if device(st) == device(parent) && inode(st) != inode(parent) {
		return result, nil
	}
	return probeMountedDefaultRoot(path)
}

func probeMountedDefaultRoot(path string) (defaultRootResult, error) {
	result := defaultRootResult{}
	// Keep even metadata checks in the child: stat/access behavior may vary by
	// filesystem and privacy policy. Never assume they cannot block.
	for _, name := range []string{"Backups.backupdb", ".timemachine"} {
		if _, err := os.Lstat(filepath.Join(path, name)); err == nil {
			return result, nil
		} else if !os.IsNotExist(err) {
			return result, err
		}
	}
	if !writable(path) {
		// Read-only volumes (Recovery, mounted images) are expected; skip quietly.
		return result, nil
	}
	// Access alone can succeed without a removable-volume privacy grant. Check
	// that open answers too, but do not enumerate or read the volume's contents.
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	err = f.Close()
	result.Include = err == nil
	return result, err
}

func (a *App) defaultRootWarning(path string, err error) {
	line := fmt.Sprintf("warning: skipping default root %q: %v; set roots explicitly or grant the binary access", path, err)
	fmt.Fprintln(a.Err, line)
	if err := a.log(line); err != nil {
		fmt.Fprintln(a.Err, "reclaimable: cannot log root warning:", err)
	}
}

// command is injectable so tests can substitute a genuinely blocking child.
// All filesystem operations on the volume, including backup-marker stats and
// listing the mount container, happen inside the timeout, before any sweep lock.
func (a *App) defaultRootsWith(volumes string, timeout float64, command func(string, string) ([]string, error)) []string {
	probe := func(mode, path string) (defaultRootResult, bool) {
		var result defaultRootResult
		argv, err := command(mode, path)
		if err == nil {
			r := runCommand(argv, timeout, "", nil)
			switch {
			case r.Timeout:
				err = fmt.Errorf("probe timed out after %gs", timeout)
			case r.Err != nil:
				err = r.Err
			case r.Code != 0:
				err = fmt.Errorf("probe failed (exit %d): %s", r.Code, r.Stderr)
			default:
				err = json.Unmarshal([]byte(r.Stdout), &result)
			}
		}
		if err != nil {
			a.defaultRootWarning(path, err)
		}
		return result, err == nil
	}
	out := []string{a.Home}
	listing, ok := probe("list", volumes)
	if !ok {
		return out
	}
	for _, name := range listing.Names {
		path := filepath.Join(volumes, name)
		if result, ok := probe("probe", path); ok && result.Include {
			out = append(out, path)
		}
	}
	return out
}
