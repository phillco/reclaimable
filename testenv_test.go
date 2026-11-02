package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testEnv struct {
	A          *App
	Cfg        *Config
	Reg        map[string]any
	Root, Jobs string
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	var err error
	root, err = filepath.EvalSymlinks(root)
	must(t, err)
	a := newApp()
	a.StateDir = filepath.Join(root, "state")
	a.ConfigDir = filepath.Join(root, "config")
	a.ConfigFile = filepath.Join(a.ConfigDir, "config.toml")
	a.ArmedFile = filepath.Join(a.ConfigDir, "armed")
	a.LogFile = filepath.Join(root, "log/reclaimable.log")
	a.Registry = filepath.Join(a.StateDir, "registry.json")
	a.LastSweep = filepath.Join(a.StateDir, "last-sweep.json")
	a.Home = root
	a.Out = &bytes.Buffer{}
	a.Err = &bytes.Buffer{}
	a.Hostname = func() string { return "fixture-host" }
	a.OpenFiles = func(string) string { return "" }
	a.ProcessCwd = func(int) string { return "" }
	jobs := filepath.Join(root, "jobs")
	must(t, os.MkdirAll(jobs, 0755))
	script := filepath.Join(root, "jobdone")
	must(t, os.WriteFile(script, []byte("#!/bin/sh\nf=\"$(dirname \"$0\")/jobs/$1\"\n[ -f \"$f\" ] || exit 2\nread -r state when < \"$f\"\n[ \"$state\" = closed ] && { echo \"$when\"; exit 0; }\n[ \"$state\" = open ] && exit 1\nexit 2\n"), 0755))
	cfg := &Config{Roots: []string{filepath.Join(root, "data")}, Floor: 0, Target: 0, DenyPaths: append([]string{}, denyPaths...), DenyNames: append([]string{}, denyNames...), DenyExact: append([]string{}, broad...), VolumeFloors: map[string]int64{}, Holders: []map[string]any{{"lease_dir": filepath.Join(root, "leases"), "claim_dir": filepath.Join(root, "claims")}}, JobDone: map[string]any{"command": []string{script, "{job}"}}, ExportFormat: "{path}", RemoteCommand: append([]string{}, defaultRemoteCommand...)}
	a.LoadConfig = func() (*Config, error) { return cfg, nil }
	return &testEnv{a, cfg, map[string]any{"markers": map[string]any{}}, root, jobs}
}
func (e *testEnv) make(t *testing.T, rel string, age float64, files map[string][]byte, fields map[string]any) string {
	t.Helper()
	f := filepath.Join(e.Root, "data", rel)
	must(t, os.MkdirAll(f, 0755))
	if files == nil {
		files = map[string][]byte{"blob.bin": bytes.Repeat([]byte("x"), 5000)}
	}
	for name, content := range files {
		p := filepath.Join(f, name)
		must(t, os.MkdirAll(filepath.Dir(p), 0755))
		must(t, os.WriteFile(p, content, 0644))
	}
	data := map[string]any{"owner": "test", "regenerate": "rerun", "holds": []any{}}
	for k, v := range fields {
		data[k] = v
	}
	b, err := json.Marshal(data)
	must(t, err)
	p := filepath.Join(f, markerName)
	must(t, os.WriteFile(p, b, 0644))
	stamp := time.Unix(0, int64((e.A.Now()-age)*1e9))
	must(t, os.Chtimes(p, stamp, stamp))
	return f
}
func (e *testEnv) setJob(t *testing.T, job, text string) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(e.Jobs, job), []byte(text), 0644))
}
func intPtr(v int64) *int64       { return &v }
func floatPtr(v float64) *float64 { return &v }
func stringPtr(v string) *string  { return &v }
func debugVerdict(v *Verdict) string {
	return fmt.Sprintf("safe=%v expired=%v reason=%s", v.Safe, v.Expired, v.Reason)
}
