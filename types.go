package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const markerName = ".reclaimable"
const day = 86400.0
const gb int64 = 1000000000
const targetMargin int64 = 20 * gb

var kinds = []string{"cache", "scratch", "worktree", "mirror", "staged"}
var defaultRemoteCommand = []string{"ssh", "{host}", "{script}"}

// App owns filesystem locations and injectable system boundaries. Production uses
// real commands; tests replace only the boundary involved in their scenario.
type App struct {
	Home, StateDir, ConfigDir, ConfigFile, ArmedFile, LogFile, Registry, LastSweep string
	Out, Err                                                                       io.Writer
	Now                                                                            func() float64
	Hostname                                                                       func() string
	Run                                                                            func([]string, float64, string, []string) Result
	RunInput                                                                       func([]string, float64, string, []string, io.Reader) Result
	OpenFiles                                                                      func(string) string
	ProcessCwd                                                                     func(int) string
	SessionRunning                                                                 func(string) string // alive, gone, no-match, unknown
	RepoState                                                                      func(string) (string, string)
	Lstat                                                                          func(string) (os.FileInfo, error)
	StatAt                                                                         func(*os.File, string, bool) (os.FileInfo, error)
	Identity                                                                       func(string) (FileIdentity, bool)
	ListDir                                                                        func(string) ([]os.DirEntry, error)
	IsMount                                                                        func(string) bool
	FSBefore                                                                       func(string, string, string)
	Rename                                                                         func(string, string) error
	FileHashes                                                                     func(string) (map[string]string, error)
	HashDir                                                                        func(*os.File, string) (map[string]string, error)
	MoveAndVerify                                                                  func(string, string, []string, map[string]string) (bool, string)
	HoldLock                                                                       func() (func(), error)
	FreeBytes                                                                      func(string) (int64, error)
	LoadConfig                                                                     func() (*Config, error)
	DefaultTTL                                                                     map[string]string
}
type Config struct {
	Maintenance                     []Maintenance
	MaintenanceArmed                bool
	Roots                           []string
	Floor, Target                   int64
	MoveRoot                        string
	DenyPaths, DenyNames, DenyExact []string
	DenySequences                   [][]string
	VolumeFloors                    map[string]int64
	Holders                         []map[string]any
	JobDone                         map[string]any
	ExportList, ExportFormat        string
	RemoteCommand                   []string
	SessionGrace                    *float64
}
type Marker struct {
	DirectoryID                                                *FileIdentity
	Folder, Owner, TTL, Regenerate, Kind, Job, Session, MoveTo string
	Holds                                                      []map[string]any
	Mtime                                                      float64
	Extra                                                      map[string]any
	JobPresent                                                 bool
}

func (m *Marker) path() string { return filepath.Join(m.Folder, markerName) }
func (m *Marker) effectiveKind() string {
	if m.Kind == "" {
		return "cache"
	}
	return m.Kind
}
func (a *App) markerTTL(m *Marker) string {
	if m.TTL != "" {
		return m.TTL
	}
	return a.DefaultTTL[m.effectiveKind()]
}

type Walk struct {
	Size           *int64
	Files          int
	Problem        string
	Repos, Crossed []string
	Markers        []string
	MarkerFolders  map[string]FileIdentity
}
type Verdict struct {
	DirectoryID                *FileIdentity
	Marker                     *Marker
	Folder                     string
	LastUsed, ClockStart, TTLS float64
	Expired, Safe              bool
	Reason                     string
	Size                       *int64
	Repo, Action, Dest         string
}
type Result struct {
	Code           int
	Stdout, Stderr string
	Err            error
	Timeout        bool
}
type Planned struct {
	V   *Verdict
	Why string
}
type Args struct {
	Only                                            string
	ForceDue                                        bool
	Command                                         string
	Path, Owner                                     string
	TTL, Regen, Kind, Job, Session, MoveTo, Subpath *string
	Paths, Roots                                    []string
	JSON, Quick, Scan, DryRun, Armed, Verbose, Off  bool
	Floor, Target                                   *int64
	Lines                                           int
}

func newApp() *App {
	home, _ := os.UserHomeDir()
	a := &App{Home: home, Out: os.Stdout, Err: os.Stderr, Now: func() float64 { return float64(time.Now().UnixNano()) / 1e9 }, DefaultTTL: map[string]string{"cache": "24h", "mirror": "3d", "scratch": "7d", "staged": "2d", "worktree": "7d"}}
	a.StateDir = filepath.Join(home, ".local/state/reclaimable")
	a.ConfigDir = filepath.Join(home, ".config/reclaimable")
	a.ConfigFile = filepath.Join(a.ConfigDir, "config.toml")
	if p := os.Getenv("RECLAIMABLE_CONFIG"); p != "" {
		a.ConfigFile = a.expand(p)
	}
	a.ArmedFile = filepath.Join(a.ConfigDir, "armed")
	a.LogFile = filepath.Join(home, ".local/log/reclaimable.log")
	a.Registry = filepath.Join(a.StateDir, "registry.json")
	a.LastSweep = filepath.Join(a.StateDir, "last-sweep.json")
	a.Hostname = func() string { h, _ := os.Hostname(); return strings.ToLower(strings.Split(h, ".")[0]) }
	a.Run = runCommand
	a.RunInput = runCommandInput
	a.Lstat = os.Lstat
	a.Identity = identity
	a.ListDir = listDir
	a.IsMount = isMount
	a.StatAt = statAt
	a.Rename = os.Rename
	a.OpenFiles = a.openFiles
	a.ProcessCwd = a.processCwd
	a.SessionRunning = a.sessionRunning
	a.RepoState = a.repoState
	a.FileHashes = a.fileHashes
	a.HashDir = a.fileHashesAt
	a.MoveAndVerify = a.moveAndVerify
	a.HoldLock = func() (func(), error) { return lockFile(filepath.Join(a.StateDir, "hold.lock")) }
	a.FreeBytes = freeBytes
	a.LoadConfig = func() (*Config, error) { return a.loadConfig(a.ConfigFile) }
	return a
}
func runCommand(argv []string, timeout float64, cwd string, env []string) Result {
	return runCommandInput(argv, timeout, cwd, env, nil)
}
func runCommandInput(argv []string, timeout float64, cwd string, env []string, input io.Reader) Result {
	if len(argv) == 0 {
		return Result{Code: -1, Err: fmt.Errorf("empty command")}
	}
	ctx := context.Background()
	cancel := func() {}
	if timeout >= 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout*float64(time.Second)))
	}
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = input
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	if env != nil {
		cmd.Env = env
	}
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	// A leader can exit while descendants keep working (even with their pipes
	// closed). Do not let those commands outlive the caller's safety lock.
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	code := 0
	if err != nil {
		code = -1
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
			if st, ok := e.Sys().(syscall.WaitStatus); ok && st.Signaled() {
				code = -int(st.Signal())
			}
			err = nil
		}
	}
	return Result{Code: code, Stdout: out.String(), Stderr: errout.String(), Err: err, Timeout: ctx.Err() == context.DeadlineExceeded}
}
func (a *App) expand(p string) string {
	if p == "~" {
		p = a.Home
	} else if strings.HasPrefix(p, "~/") {
		p = filepath.Join(a.Home, p[2:])
	}
	p = filepath.Clean(p)
	absolute, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return stripData(absolute)
}

func (a *App) resolveFolder(p string) string {
	p = a.expand(p)
	if fold(filepath.Base(p)) == fold(markerName) {
		p = filepath.Dir(p)
	}
	return p
}
func (a *App) stateLock() (func(), error) { return lockFile(filepath.Join(a.StateDir, "state.lock")) }
func lockFile(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func loadJSON(path string, fallback any) (any, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return fallback, nil
	}
	if e != nil {
		return nil, e
	}
	var v any
	e = json.Unmarshal(b, &v)
	return v, e
}
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func dict(v any) map[string]any { m, _ := v.(map[string]any); return m }
func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}
func textValue(v any) string {
	if v == nil {
		return ""
	}
	if b, ok := v.(bool); ok {
		if b {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}
func truth(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		return number(x) != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case int64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
func stringList(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		out := make([]string, 0, len(x))
		for _, v := range x {
			s, ok := v.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
func mapEntry(m map[string]any, key string) map[string]any {
	v := dict(m[key])
	if v == nil {
		v = map[string]any{}
		m[key] = v
	}
	return v
}
func markerEntry(reg map[string]any, folder string, now float64) map[string]any {
	markers := mapEntry(reg, "markers")
	e := dict(markers[folder])
	if e == nil {
		e = map[string]any{"registered": now}
		markers[folder] = e
	}
	return e
}
func related(a, b string) bool   { return within(a, b) || within(b, a) }
func within(p, root string) bool { return keyWithin(pathKey(p), pathKey(root)) }
func keyWithin(child, parent string) bool {
	return child == parent || parent == "/" || strings.HasPrefix(child, parent+"/")
}
func device(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
func inode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
func allocated(info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return info.Size()
}
func isFile(p string) bool { s, e := os.Stat(p); return e == nil && s.Mode().IsRegular() }
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func isDir(p string) bool  { s, e := os.Stat(p); return e == nil && s.IsDir() }
func isMount(p string) bool {
	absolute, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	p = absolute
	s, e := os.Stat(p)
	if e != nil {
		return false
	}
	parent, e := os.Stat(filepath.Dir(p))
	return e == nil && (device(s) != device(parent) || inode(s) == inode(parent))
}
func pidAlive(pid int) bool { return syscall.Kill(pid, 0) != syscall.ESRCH }
func freeBytes(p string) (int64, error) {
	var s syscall.Statfs_t
	e := syscall.Statfs(p, &s)
	return int64(s.Bavail) * int64(s.Bsize), e
}
func (a *App) log(line string) error {
	if e := os.MkdirAll(filepath.Dir(a.LogFile), 0755); e != nil {
		return e
	}
	f, e := os.OpenFile(a.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	ts := time.Unix(0, int64(a.Now()*1e9))
	_, e = fmt.Fprintf(f, "%s %s %s\n", ts.Format("2006-01-02"), clock(a.Now()), line)
	return e
}
