package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDefaultRootBlockedOpener(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--root-test-open" {
		return
	}
	// Opening a FIFO without a writer really blocks in open(2), like a stalled
	// mount/consent request, rather than merely returning a fake timeout result.
	f, err := os.Open(os.Args[len(os.Args)-1])
	if err == nil {
		f.Close()
	}
	os.Exit(1)
}

func TestDefaultRootsBlockedProbeDoesNotBlockSweep(t *testing.T) {
	for _, blocked := range []string{"list", "probe"} {
		t.Run(blocked, func(t *testing.T) {
			e := newTestEnv(t)
			volumes := filepath.Join(e.Root, "volumes")
			slow, ready := filepath.Join(volumes, "a-stalled"), filepath.Join(volumes, "b-ready")
			must(t, os.MkdirAll(slow, 0755))
			must(t, os.MkdirAll(ready, 0755))
			fifo := filepath.Join(e.Root, "blocked-open")
			must(t, syscall.Mkfifo(fifo, 0600))
			executable, err := os.Executable()
			must(t, err)
			factory := func(mode, path string) ([]string, error) {
				if mode == blocked && (mode == "list" || path == slow) {
					return []string{executable, "-test.run=^TestDefaultRootBlockedOpener$", "--", "--root-test-open", fifo}, nil
				}
				if mode == "list" {
					return defaultRootCommand(mode, path)
				}
				return []string{"/bin/sh", "-c", `printf '{"include":true}'`}, nil
			}
			e.A.LoadConfig = func() (*Config, error) {
				e.Cfg.Roots = e.A.defaultRootsWith(volumes, 0.2, factory)
				return e.Cfg, nil
			}
			start := time.Now()
			code := e.A.main([]string{"sweep", "-nS"})
			check(t, time.Since(start) < 3*time.Second, "sweep did not respect probe deadline")
			check(t, code == 0, "sweep failed: %s", e.A.Err)
			want := []string{e.A.Home}
			warningPath := volumes
			if blocked == "probe" {
				want = append(want, ready)
				warningPath = slow
			}
			check(t, reflect.DeepEqual(e.Cfg.Roots, want), "roots = %v, want %v", e.Cfg.Roots, want)
			log, err := os.ReadFile(e.A.LogFile)
			must(t, err)
			for _, output := range []string{string(log), e.A.Err.(*bytes.Buffer).String()} {
				for _, text := range []string{warningPath, "timed out", "set roots explicitly", "grant the binary access"} {
					check(t, strings.Contains(output, text), "missing %q in %s", text, output)
				}
			}
		})
	}
}

func TestDefaultRootWorkerMetadata(t *testing.T) {
	e := newTestEnv(t)
	plain := filepath.Join(e.Root, "ordinary-directory")
	link := filepath.Join(e.Root, "directory-link")
	must(t, os.Mkdir(plain, 0755))
	must(t, os.Symlink(plain, link))
	for _, path := range []string{plain, link} {
		argv, err := defaultRootCommand("probe", path)
		must(t, err)
		r := runCommand(argv, 2, "", nil)
		var result defaultRootResult
		must(t, json.Unmarshal([]byte(r.Stdout), &result))
		check(t, r.Code == 0 && r.Err == nil && !r.Timeout && !result.Include, "non-mount admitted: %s %+v", path, r)
	}
	result, err := probeDefaultRoot("probe", filepath.Join(e.Root, "missing"))
	check(t, os.IsNotExist(err) && !result.Include, "missing root admitted: %+v %v", result, err)
}

func TestExplicitRootsBypassDefaultProbes(t *testing.T) {
	e := newTestEnv(t)
	path := filepath.Join(e.Root, "unavailable", "selected")
	must(t, atomicWrite(e.A.ConfigFile, []byte("roots = ["+pyRepr(path)+"]\n"), 0600))
	cfg, err := e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	check(t, reflect.DeepEqual(cfg.Roots, []string{path}), "explicit roots changed: %v", cfg.Roots)
	check(t, e.A.Err.(*bytes.Buffer).Len() == 0, "explicit roots triggered warning: %s", e.A.Err)
}

func TestDefaultMountedRootFilters(t *testing.T) {
	for _, indicator := range []string{"", "Backups.backupdb", ".timemachine", "dangling-backup-link"} {
		t.Run(indicator, func(t *testing.T) {
			root := t.TempDir()
			if indicator == "dangling-backup-link" {
				must(t, os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, ".timemachine")))
			} else if indicator != "" {
				must(t, os.Mkdir(filepath.Join(root, indicator), 0755))
			}
			result, err := probeMountedDefaultRoot(root)
			must(t, err)
			check(t, result.Include == (indicator == ""), "incorrect mount filtering: %+v", result)
		})
	}
}
