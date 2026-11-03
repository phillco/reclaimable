package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func safetyWrite(t *testing.T, path, text string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0755))
	must(t, os.WriteFile(path, []byte(text), 0644))
}
func safetyRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	return string(b)
}
func safetyEval(e *testEnv, f string) *Verdict { return e.A.evaluate(f, e.Cfg, e.Reg, true) }
func safetyPgrep(t *testing.T, a *App, code int) {
	t.Helper()
	bin := t.TempDir()
	must(t, os.WriteFile(filepath.Join(bin, "pgrep"), []byte("#!/bin/sh\nexit 1\n"), 0755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	real := a.Run
	a.Run = func(cmd []string, timeout float64, cwd string, env []string) Result {
		if cmd[0] == "pgrep" {
			out := ""
			if code == 0 {
				out = "4242\n"
			}
			return Result{Code: code, Stdout: out}
		}
		return real(cmd, timeout, cwd, env)
	}
}
func isoAgo(a *App, s float64) string {
	return time.Unix(int64(a.Now()-s), 0).UTC().Format("2006-01-02T15:04:05Z")
}
func TestLiveLeaseReferencingFolderHolds(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "leased", 9*day, nil, nil)
	p := filepath.Join(e.Root, "leases/1.json")
	must(t, writeJSON(p, map[string]any{"job": "x", "pid": os.Getpid(), "log": filepath.Join(f, "run.log")}))
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "lease"), "%+v", v)
	must(t, writeJSON(p, map[string]any{"job": "x", "pid": 999999, "log": filepath.Join(f, "run.log")}))
	check(t, safetyEval(e, f).Safe, "dead lease holds")
}
func TestLeaseForSameJobHolds(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "leased", 9*day, nil, map[string]any{"job": "7", "kind": "scratch"})
	e.setJob(t, "7", "closed 2020-01-01T00:00:00Z")
	must(t, writeJSON(filepath.Join(e.Root, "leases/1.json"), map[string]any{"job": "7", "pid": os.Getpid()}))
	check(t, strings.Contains(safetyEval(e, f).Reason, "is this job"), "job lease not held")
}
func TestLeaseDirGlob(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "g", 9*day, nil, nil)
	must(t, writeJSON(filepath.Join(e.Root, "u1/leases/1.json"), map[string]any{"pid": os.Getpid(), "what": f}))
	e.Cfg.Holders = []map[string]any{{"lease_dir": filepath.Join(e.Root, "u*/leases")}}
	check(t, strings.Contains(safetyEval(e, f).Reason, "lease"), "glob ignored lease")
}
func TestMalformedLeaseFailsClosed(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "x", 9*day, nil, nil)
	safetyWrite(t, filepath.Join(e.Root, "leases/2.json"), "{nope")
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "unreadable lease"), "%+v", v)
}
func TestRunningClaimRecordHolds(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "claimed", 9*day, nil, nil)
	must(t, writeJSON(filepath.Join(e.Root, "claims/abc.json"), map[string]any{"state": "starting", "cwd": f}))
	check(t, strings.Contains(safetyEval(e, f).Reason, "claim abc"), "claim ignored")
}
func TestCommandHolderExitCodes(t *testing.T) {
	for _, code := range []int{0, 1, 2, 127} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "h", 9*day, nil, nil)
			e.Cfg.Holders = []map[string]any{{"command": []string{"sh", "-c", fmt.Sprintf("echo busy; exit %d", code), "x", "{path}"}, "name": "chk"}}
			v := safetyEval(e, f)
			check(t, v.Safe == (code == 1), "code %d: %+v", code, v)
			if code == 0 {
				check(t, strings.Contains(v.Reason, "chk: busy"), "%+v", v)
			}
		})
	}
}
func TestCommandHolderGetsMarkerFields(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "h", 9*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	e.setJob(t, "9", "closed 2020-01-01T00:00:00Z")
	out := filepath.Join(e.Root, "seen")
	e.Cfg.Holders = []map[string]any{{"command": []string{"sh", "-c", `echo "$1 $2 $3 $4 $RECLAIMABLE_PATH $RECLAIMABLE_JOB" > "$5"; exit 1`, "x", "{path}", "{owner}", "{kind}", "{job}", out}}}
	v := safetyEval(e, f)
	check(t, v.Safe, "%+v", v)
	check(t, reflect.DeepEqual(strings.Fields(safetyRead(t, out)), []string{f, "test", "scratch", "9", f, "9"}), "holder fields %q", safetyRead(t, out))
}
func TestCommandHolderTimeoutAndMissingFailClosed(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "h", 9*day, nil, nil)
	e.Cfg.Holders = []map[string]any{{"command": []string{"sleep", "5"}, "timeout": 0.2}}
	check(t, strings.Contains(safetyEval(e, f).Reason, "timed out"), "timeout not held")
	e.Cfg.Holders = []map[string]any{{"command": []string{"/nonexistent/holder"}}}
	check(t, !safetyEval(e, f).Safe, "missing command not held")
}
func TestConfigDirPlaceholder(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "h", 9*day, nil, nil)
	safetyWrite(t, e.A.ConfigFile, "")
	helper := filepath.Join(filepath.Dir(e.A.ConfigFile), "veto")
	safetyWrite(t, helper, "#!/bin/sh\nexit 0\n")
	must(t, os.Chmod(helper, 0755))
	e.Cfg.Holders = []map[string]any{{"command": []string{"{config_dir}/veto"}}}
	check(t, !safetyEval(e, f).Safe, "placeholder ignored")
}
func TestOpenFilesBlock(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "busy", 9*day, nil, nil)
	e.A.OpenFiles = func(string) string { return "open files: python[1]" }
	check(t, !safetyEval(e, f).Safe, "open files ignored")
}
func TestJobOpenBlocks(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "123", "open")
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "123", "kind": "scratch"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "job 123 open"), "%+v", v)
}
func TestJobUnknownOrUnconfiguredNotEligible(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "j", 30*day, nil, map[string]any{"job": "nope"})
	check(t, strings.Contains(safetyEval(e, f).Reason, "unknown"), "unknown job ignored")
	e.Cfg.JobDone = nil
	check(t, !safetyEval(e, e.make(t, "k", 30*day, nil, map[string]any{"job": "1"})).Safe, "unconfigured job ignored")
}
func TestJobClosedButSessionRunningBlocks(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "5", "closed 2020-01-01T00:00:00Z")
	safetyPgrep(t, e.A, 0)
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "still running"), "%+v", v)
}
func TestPgrepMissIsUnknownNotExited(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "5", "closed 2020-01-01T00:00:00Z")
	safetyPgrep(t, e.A, 1)
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "unknown"), "%+v", v)
	check(t, safetyEval(e, e.make(t, "k", 30*day, nil, map[string]any{"job": "5", "session": "999999"})).Safe, "dead pid not gone")
}
func TestTtlCountsFromJobCloseAndSessionExit(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "5", "closed "+isoAgo(e.A, day))
	f := e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "999999", "kind": "scratch"})
	v := safetyEval(e, f)
	check(t, v.Safe && !v.Expired, "%+v", v)
	e.Reg["jobs"] = map[string]any{}
	markerEntry(e.Reg, f, e.A.Now())["session_exit_seen"] = e.A.Now() - 8*day
	e.setJob(t, "5", "closed 2020-01-01T00:00:00Z")
	check(t, safetyEval(e, f).Expired, "TTL ignored session exit")
}
func TestMirrorDescendantDenyNamesApply(t *testing.T) {
	for _, rel := range []string{"x/models/w.bin", "a/closed-receipt.json"} {
		t.Run(rel, func(t *testing.T) {
			e := newTestEnv(t)
			e.Cfg.DenyNames = append(e.Cfg.DenyNames, "models", "*receipt*")
			f := e.make(t, "mir", 30*day, map[string][]byte{rel: []byte("1")}, map[string]any{"kind": "mirror"})
			v := safetyEval(e, f)
			check(t, !v.Safe && strings.Contains(v.Reason, "deny-listed"), "%+v", v)
		})
	}
}

func gitTest(t *testing.T, cwd string, args ...string) {
	t.Helper()
	r := runCommand(append([]string{"git"}, args...), 60, cwd, nil)
	check(t, r.Err == nil && r.Code == 0, "git %v: %v %s", args, r.Err, r.Stderr)
}
func makeRepoWithRemote(t *testing.T, e *testEnv) string {
	t.Helper()
	origin := filepath.Join(e.Root, "origin.git")
	gitTest(t, e.Root, "init", "--bare", "-q", origin)
	main := filepath.Join(e.Root, "main")
	gitTest(t, e.Root, "init", "-q", "-b", "main", main)
	gitTest(t, main, "config", "user.email", "t@t")
	gitTest(t, main, "config", "user.name", "t")
	safetyWrite(t, filepath.Join(main, "a"), "1")
	gitTest(t, main, "add", "a")
	gitTest(t, main, "commit", "-qm", "a")
	gitTest(t, main, "remote", "add", "origin", origin)
	gitTest(t, main, "push", "-q", "origin", "HEAD:refs/heads/main")
	return main
}
func TestDirtyAndUnpushedWorktreesRefused(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	wt := filepath.Join(e.Root, "data/wt")
	gitTest(t, main, "worktree", "add", "-q", "--detach", wt)
	must(t, writeJSON(filepath.Join(wt, markerName), map[string]any{"owner": "t", "regenerate": "git worktree add", "kind": "worktree"}))
	old := time.Unix(int64(e.A.Now()-30*day), 0)
	must(t, os.Chtimes(filepath.Join(wt, markerName), old, old))
	v := safetyEval(e, wt)
	check(t, v.Safe && v.Repo == "git-linked", "%+v", v)
	safetyWrite(t, filepath.Join(wt, "b"), "2")
	check(t, strings.Contains(safetyEval(e, wt).Reason, "dirty"), "dirty worktree allowed")
	gitTest(t, wt, "add", "b")
	gitTest(t, wt, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b")
	check(t, strings.Contains(safetyEval(e, wt).Reason, "unpushed"), "unpushed worktree allowed")
	must(t, writeJSON(filepath.Join(main, markerName), map[string]any{"owner": "t", "regenerate": "clone"}))
	must(t, os.Chtimes(filepath.Join(main, markerName), old, old))
	check(t, strings.Contains(safetyEval(e, main).Reason, "git-primary"), "primary repo allowed")
}
func TestMirrorStillChecksNestedRepos(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	f := e.make(t, "mir", 30*day, nil, map[string]any{"kind": "mirror"})
	gitTest(t, e.Root, "clone", "-q", main, filepath.Join(f, "inner"))
	safetyWrite(t, filepath.Join(f, "inner/dirty"), "x")
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "nested repo inner"), "%+v", v)
}
func TestNestedPrimaryRepoInMirrorRefused(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	f := e.make(t, "mir2", 30*day, nil, map[string]any{"kind": "mirror"})
	gitTest(t, e.Root, "clone", "-q", main, filepath.Join(f, "inner"))
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "nested git-primary"), "%+v", v)
	g := e.make(t, "mir3", 30*day, nil, map[string]any{"kind": "mirror"})
	gitTest(t, main, "worktree", "add", "-q", "--detach", filepath.Join(g, "wt"))
	check(t, safetyEval(e, g).Safe, "linked nested worktree refused: %+v", safetyEval(e, g))
}

func TestSessionGraceUnsetKeepsUnobservableSession(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
	safetyPgrep(t, e.A, 1)
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "unknown"), "%+v", v)
}
func TestSessionGraceNotElapsedKeeps(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(72 * 3600)
	e.setJob(t, "5", "closed "+isoAgo(e.A, day))
	safetyPgrep(t, e.A, 1)
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "within grace"), "%+v", v)
}
func TestSessionGraceElapsedCountsAsGone(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3 * day)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 10*day))
	safetyPgrep(t, e.A, 1)
	v := safetyEval(e, e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"}))
	check(t, v.Safe && v.Expired, "%+v", v)
	age := e.A.Now() - v.ClockStart
	check(t, age > 6.9*day && age < 7.1*day, "clock age %f", age)
}
func TestMissingCloseTimeCountsFromFirstObservation(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(72 * 3600)
	e.setJob(t, "5", "closed")
	safetyPgrep(t, e.A, 1)
	f := e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "within grace"), "%+v", v)
	jobs := mapEntry(e.Reg, "jobs")
	record := dict(jobs["5"])
	first := number(record["first_closed_seen"])
	record["checked"] = number(record["checked"]) - 7200
	safetyEval(e, f)
	record = dict(jobs["5"])
	check(t, number(record["first_closed_seen"]) == first, "first observation changed")
	record["first_closed_seen"] = first - 4*day
	record["closed_at"] = first - 4*day
	check(t, safetyEval(e, f).Safe, "grace failed after first observation")
	e.setJob(t, "6", "closed garbage")
	g := safetyEval(e, e.make(t, "k", 30*day, nil, map[string]any{"job": "6", "session": "sess-x"}))
	check(t, !g.Safe && strings.Contains(g.Reason, "within grace"), "%+v", g)
}
func TestMissingCloseTimeTtlCountsFromFirstObservation(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "7", "closed")
	v := safetyEval(e, e.make(t, "t", 30*day, nil, map[string]any{"job": "7", "kind": "scratch"}))
	check(t, v.Safe && !v.Expired, "%+v", v)
}
func TestSessionGraceRequiresSuccessfulNomatchProbe(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3600)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
	f := e.make(t, "j", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	check(t, !safetyEval(e, f).Safe, "missing pgrep allowed")
	t.Setenv("PATH", originalPath)
	safetyPgrep(t, e.A, 2)
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "unknown"), "%+v", v)
	e.A.Run = func([]string, float64, string, []string) Result {
		return Result{Timeout: true, Err: errors.New("timeout"), Code: -1}
	}
	check(t, !safetyEval(e, f).Safe, "timeout allowed")
	safetyPgrep(t, e.A, 1)
	check(t, safetyEval(e, f).Safe, "successful no-match rejected")
}
func TestUnreadableLeaseAndClaimDirsFailClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	e := newTestEnv(t)
	f := e.make(t, "x", 9*day, nil, nil)
	leases := filepath.Join(e.Root, "leases")
	must(t, writeJSON(filepath.Join(leases, "1.json"), map[string]any{"pid": os.Getpid(), "what": f}))
	must(t, os.Chmod(leases, 0))
	defer os.Chmod(leases, 0755)
	v := safetyEval(e, f)
	must(t, os.Chmod(leases, 0755))
	check(t, !v.Safe && strings.Contains(v.Reason, "unreadable"), "%+v", v)
	// Remove the earlier matching lease so the claim-directory check is reached.
	must(t, os.Remove(filepath.Join(leases, "1.json")))
	claims := filepath.Join(e.Root, "claims")
	must(t, writeJSON(filepath.Join(claims, "a.json"), map[string]any{"state": "running", "pid": os.Getpid(), "cwd": f}))
	must(t, os.Chmod(claims, 0))
	defer os.Chmod(claims, 0755)
	v = safetyEval(e, f)
	must(t, os.Chmod(claims, 0755))
	check(t, !v.Safe && strings.Contains(v.Reason, "unreadable"), "%+v", v)
	must(t, writeJSON(filepath.Join(leases, "1.json"), map[string]any{"pid": os.Getpid(), "claim_id": "a"}))
	must(t, os.Chmod(claims, 0))
	check(t, !safetyEval(e, f).Safe, "claim in unreadable dir ignored")
	must(t, os.Chmod(claims, 0755))
}
func TestUnreadableDirInsideLeaseGlobFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	e := newTestEnv(t)
	f := e.make(t, "x", 9*day, nil, nil)
	base := filepath.Join(e.Root, "homes")
	must(t, os.MkdirAll(filepath.Join(base, "u1/leases"), 0755))
	must(t, os.MkdirAll(filepath.Join(base, "u2"), 0755))
	e.Cfg.Holders = []map[string]any{{"lease_dir": filepath.Join(base, "*/leases")}}
	check(t, safetyEval(e, f).Safe, "missing lease dir held")
	must(t, os.Chmod(filepath.Join(base, "u2"), 0))
	defer os.Chmod(filepath.Join(base, "u2"), 0755)
	check(t, !safetyEval(e, f).Safe, "unreadable possible lease dir ignored")
	must(t, os.Chmod(filepath.Join(base, "u2"), 0755))
	must(t, os.Chmod(base, 0))
	defer os.Chmod(base, 0755)
	check(t, !safetyEval(e, f).Safe, "unreadable glob parent ignored")
	must(t, os.Chmod(base, 0755))
}
func TestSessionGraceNeedsClosedJobAndIgnoresPidsAndLiveHits(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3600)
	e.setJob(t, "5", "open")
	safetyPgrep(t, e.A, 1)
	check(t, !safetyEval(e, e.make(t, "o", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})).Safe, "open job ignored")
	e.setJob(t, "6", "closed "+isoAgo(e.A, 30*day))
	safetyPgrep(t, e.A, 0)
	v := safetyEval(e, e.make(t, "h", 30*day, nil, map[string]any{"job": "6", "session": "sess-x"}))
	check(t, !v.Safe && strings.Contains(v.Reason, "still running"), "%+v", v)
	live := safetyEval(e, e.make(t, "p", 30*day, nil, map[string]any{"job": "6", "session": strconv.Itoa(os.Getpid())}))
	check(t, !live.Safe && strings.Contains(live.Reason, "still running"), "%+v", live)
	check(t, safetyEval(e, e.make(t, "d", 30*day, nil, map[string]any{"job": "6", "session": "999999"})).Safe, "dead pid still held")
}

func TestSystemProbesFailClosed(t *testing.T) {
	e := newTestEnv(t)
	bin := t.TempDir()
	for _, name := range []string{"lsof", "pgrep"} {
		p := filepath.Join(bin, name)
		must(t, os.WriteFile(p, []byte("#!/bin/sh\nexit 1\n"), 0755))
	}
	t.Setenv("PATH", bin)
	for _, tc := range []struct {
		name string
		r    Result
		want string
	}{
		{"free", Result{Code: 1}, ""},
		{"failure", Result{Code: 2}, "lsof failed (2)"},
		{"timeout", Result{Timeout: true}, "lsof timed out"},
		{"missing", Result{Code: -1, Err: os.ErrNotExist}, "lsof failed (-1)"},
		{"reader", Result{Code: 0, Stdout: "p42\ncworker\nn/file\n"}, "open files: worker[42]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.A.Run = func([]string, float64, string, []string) Result { return tc.r }
			check(t, e.A.openFiles(e.Root) == tc.want, "got %q want %q", e.A.openFiles(e.Root), tc.want)
		})
	}
	for _, tc := range []struct {
		name string
		r    Result
		want string
	}{
		{"no-match", Result{Code: 1}, "no-match"},
		{"self-only", Result{Code: 0, Stdout: strconv.Itoa(os.Getpid())}, "no-match"},
		{"live", Result{Code: 0, Stdout: "4242"}, "alive"},
		{"failure", Result{Code: 2}, "unknown"},
		{"timeout", Result{Timeout: true}, "unknown"},
		{"missing", Result{Err: os.ErrNotExist}, "unknown"},
	} {
		t.Run("session-"+tc.name, func(t *testing.T) {
			e.A.Run = func([]string, float64, string, []string) Result { return tc.r }
			check(t, e.A.sessionRunning("text-session") == tc.want, "got %q", e.A.sessionRunning("text-session"))
		})
	}
	t.Setenv("PATH", t.TempDir())
	check(t, e.A.openFiles(e.Root) == "lsof unavailable" && e.A.sessionRunning("text-session") == "unknown", "missing probes must fail closed")
}

func TestMalformedLeaseAndClaimObjectsFailClosed(t *testing.T) {
	for _, body := range []string{"null", "[]", "{}", `{"pid":"oops"}`} {
		t.Run("lease-"+body, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "data", 9*day, nil, nil)
			safetyWrite(t, filepath.Join(e.Root, "leases/l.json"), body)
			v := safetyEval(e, f)
			check(t, !v.Safe && strings.Contains(v.Reason, "unreadable lease"), "%+v", v)
		})
	}
	for _, body := range []string{"null", "[]", `{"state":"running","pid":"oops"}`} {
		t.Run("claim-"+body, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "data", 9*day, nil, nil)
			safetyWrite(t, filepath.Join(e.Root, "claims/c.json"), body)
			v := safetyEval(e, f)
			check(t, !v.Safe && strings.Contains(v.Reason, "unreadable claim"), "%+v", v)
		})
	}
}

func TestSecondaryWorkspaceSafety(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "workspace", 30*day, map[string][]byte{".jj/repo": []byte("store")}, map[string]any{"kind": "worktree"})
	var calls [][]string
	e.A.Run = func(cmd []string, timeout float64, cwd string, env []string) Result {
		calls = append(calls, append([]string{}, cmd...))
		return Result{Code: 0}
	}
	v := safetyEval(e, f)
	check(t, v.Safe && v.Repo == "jj-secondary" && len(calls) == 4, "%+v calls=%v", v, calls)
	// Both the stored snapshot and the live working copy must be clean.
	for _, live := range []bool{false, true} {
		t.Run(fmt.Sprint(live), func(t *testing.T) {
			e.A.Run = func(cmd []string, timeout float64, cwd string, env []string) Result {
				isDiff := contains(cmd, "diff")
				stored := contains(cmd, "--ignore-working-copy")
				if isDiff && stored != live {
					return Result{Code: 0, Stdout: "valuable.txt\n"}
				}
				return Result{Code: 0}
			}
			v := safetyEval(e, f)
			check(t, !v.Safe && strings.Contains(v.Reason, "dirty"), "%+v", v)
		})
	}
	e.A.Run = func(cmd []string, timeout float64, cwd string, env []string) Result {
		if contains(cmd, "log") {
			return Result{Code: 0, Stdout: "unpublished\n"}
		}
		return Result{Code: 0}
	}
	check(t, !safetyEval(e, f).Safe, "unpushed secondary workspace allowed")
	e.A.Run = func([]string, float64, string, []string) Result { return Result{Err: os.ErrNotExist, Code: -1} }
	check(t, !safetyEval(e, f).Safe, "unavailable workspace command allowed")
}

func TestNegativeConfiguredTimeoutIsImmediate(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "h", 9*day, nil, nil)
	e.Cfg.Holders = []map[string]any{{"command": []string{"sleep", "10"}, "timeout": -1.0}}
	start := time.Now()
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "timed out") && time.Since(start) < time.Second, "negative timeout was unbounded: %+v", v)
	e.Cfg.Holders = nil
	e.Cfg.JobDone = map[string]any{"command": []string{"sleep", "10"}, "timeout": -1.0}
	f = e.make(t, "j", 9*day, nil, map[string]any{"job": "1"})
	v = safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "timed out") && time.Since(start) < time.Second, "negative job timeout was unbounded: %+v", v)
}

func TestFreshJobCheckBypassesPositiveCache(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		wantClosed *bool
		wantDetail string
	}{
		{"reopened", "open", func() *bool { v := false; return &v }(), "open"},
		{"unknown", "unknown", nil, "job_done exited 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.setJob(t, "job", "closed 2020-01-01T00:00:00Z")
			closed, _, _ := e.A.jobClosed("job", e.Cfg, e.Reg)
			check(t, closed != nil && *closed, "initial job not closed")
			e.setJob(t, "job", tc.text)
			cached, _, _ := e.A.jobClosed("job", e.Cfg, e.Reg)
			check(t, cached != nil && *cached, "evaluation cache unexpectedly bypassed")
			fresh, _, detail := e.A.jobClosedFresh("job", e.Cfg, e.Reg)
			check(t, (fresh == nil && tc.wantClosed == nil) || (fresh != nil && tc.wantClosed != nil && *fresh == *tc.wantClosed), "fresh close = %v detail=%s", fresh, detail)
			check(t, detail == tc.wantDetail, "fresh detail %q", detail)
			record := dict(mapEntry(e.Reg, "jobs")["job"])
			check(t, !truth(record["closed"]), "stale positive cache retained: %+v", record)
		})
	}
	for _, tc := range []struct {
		name   string
		result Result
		want   string
	}{
		{"missing", Result{Code: -1, Err: os.ErrNotExist}, "failed to run"},
		{"timeout", Result{Timeout: true}, "timed out"},
		{"failed", Result{Code: 2}, "exited 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.setJob(t, "job", "closed 2020-01-01T00:00:00Z")
			closed, _, _ := e.A.jobClosed("job", e.Cfg, e.Reg)
			check(t, closed != nil && *closed, "initial job not closed")
			calls := 0
			e.A.Run = func([]string, float64, string, []string) Result { calls++; return tc.result }
			closed, _, detail := e.A.jobClosedFresh("job", e.Cfg, e.Reg)
			check(t, closed == nil && calls == 1 && strings.Contains(detail, tc.want), "fresh error accepted: closed=%v calls=%d detail=%s", closed, calls, detail)
			_, cached := mapEntry(e.Reg, "jobs")["job"]
			check(t, !cached, "stale job cache retained after %s", tc.name)
			e.A.jobClosed("job", e.Cfg, e.Reg)
			check(t, calls == 2, "failed fresh probe leaked positive cache to later evaluation")
		})
	}
}

func TestFreshJobCheckPreservesFirstObservedClose(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "job", "closed")
	_, first, detail := e.A.jobClosed("job", e.Cfg, e.Reg)
	check(t, first != nil && detail == "closed", "initial observation missing")
	observed := *first
	originalNow := e.A.Now()
	e.A.Now = func() float64 { return originalNow + 7200 }
	closed, again, detail := e.A.jobClosedFresh("job", e.Cfg, e.Reg)
	check(t, closed != nil && *closed && again != nil && *again == observed && detail == "closed", "fresh check reset first observation: %v %v %s", closed, again, detail)
	record := dict(mapEntry(e.Reg, "jobs")["job"])
	check(t, number(record["first_closed_seen"]) == observed && number(record["checked"]) == originalNow+7200, "fresh registry %+v", record)
}

func TestChildStatFailureBlocksWalkAndRemoval(t *testing.T) {
	for _, rel := range []string{"plain.bin", "sub"} {
		t.Run(rel, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "tree", 30*day, map[string][]byte{"plain.bin": []byte("valuable"), "sub/nested.bin": []byte("valuable")}, nil)
			initial := safetyEval(e, f)
			check(t, initial.Safe, "initial fixture not eligible: %+v", initial)
			real := e.A.StatAt
			failed := filepath.Join(f, rel)
			e.A.StatAt = func(parent *os.File, name string, follow bool) (os.FileInfo, error) {
				if name == rel {
					return nil, &os.PathError{Op: "fstatat", Path: failed, Err: os.ErrPermission}
				}
				return real(parent, name, follow)
			}
			w := e.A.walk(f, e.Cfg, true, 300)
			check(t, w.Size == nil && strings.Contains(w.Problem, "unreadable") && strings.Contains(w.Problem, failed), "stat failure produced completed walk: %+v", w)
			v := safetyEval(e, f)
			check(t, !v.Safe && strings.Contains(v.Reason, "unreadable"), "stat failure accepted: %+v", v)
			ok, detail := e.A.removeFolder(initial, true, e.Cfg, e.Reg)
			check(t, !ok && strings.Contains(detail, "unreadable") && exists(filepath.Join(f, "sub/nested.bin")) && exists(filepath.Join(f, "plain.bin")), "stat failure removed source: %v %s", ok, detail)
		})
	}
}

func TestNumericSessionAliveAfterEvaluationBlocksRemoval(t *testing.T) {
	e := newTestEnv(t)
	dead := exec.Command("sleep", "30")
	must(t, dead.Start())
	must(t, dead.Process.Kill())
	_ = dead.Wait()
	f := e.make(t, "ss1", 30*day, nil, map[string]any{"session": strconv.Itoa(dead.Process.Pid)})
	v := safetyEval(e, f)
	check(t, v.Safe, "%s", debugVerdict(v))
	live := exec.Command("sleep", "30")
	must(t, live.Start())
	defer func() { _ = live.Process.Kill(); _ = live.Wait() }()
	st, err := os.Stat(filepath.Join(f, markerName))
	must(t, err)
	m, err := e.A.readMarker(f)
	must(t, err)
	m.Session = strconv.Itoa(live.Process.Pid)
	must(t, e.A.writeMarker(m))
	must(t, os.Chtimes(filepath.Join(f, markerName), st.ModTime(), st.ModTime()))
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "still running"), "%v %s", ok, detail)
}

func TestSessionAppearingAliveBetweenEvaluateAndRemovalIsKept(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3600)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
	safetyPgrep(t, e.A, 1)
	f := e.make(t, "ss2", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})
	v := safetyEval(e, f)
	check(t, v.Safe, "%s", debugVerdict(v))
	safetyPgrep(t, e.A, 0)
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "still running"), "%v %s", ok, detail)
	check(t, markerEntry(e.Reg, f, e.A.Now())["session_exit_seen"] == nil, "live session retained exit observation")
}

func TestSessionProbeFailingAtRemovalIsKept(t *testing.T) {
	for _, code := range []int{2, -1} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			e := newTestEnv(t)
			e.Cfg.SessionGrace = floatPtr(3600)
			e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
			safetyPgrep(t, e.A, 1)
			f := e.make(t, "ss3", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})
			v := safetyEval(e, f)
			check(t, v.Safe, "%s", debugVerdict(v))
			if code == 2 {
				safetyPgrep(t, e.A, 2)
			} else {
				// Keep the scheduler helper runnable while making pgrep unavailable.
				dirname, err := exec.LookPath("dirname")
				must(t, err)
				bin := t.TempDir()
				must(t, os.Symlink(dirname, filepath.Join(bin, "dirname")))
				t.Setenv("PATH", bin)
			}
			ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
			check(t, !ok && exists(f) && strings.Contains(detail, "session sess-x state unknown"), "%v %s", ok, detail)
			check(t, markerEntry(e.Reg, f, e.A.Now())["session_exit_seen"] == nil, "unknown session retained exit observation")
		})
	}
}

func TestSessionAliveDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3600)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
	safetyPgrep(t, e.A, 1)
	f, _ := makeMovable(t, e, "ss4")
	m, err := e.A.readMarker(f)
	must(t, err)
	m.Job = "5"
	m.Session = "sess-x"
	must(t, e.A.writeMarker(m))
	removalAge(t, f, 30*day)
	v := safetyEval(e, f)
	check(t, v.Safe && v.Action == "move", "%s", debugVerdict(v))
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		safetyPgrep(t, e.A, 0)
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "still running"), "%v %s", ok, detail)
}

func TestSessionStillGoneAtRemovalRemoves(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.SessionGrace = floatPtr(3600)
	e.setJob(t, "5", "closed "+isoAgo(e.A, 30*day))
	safetyPgrep(t, e.A, 1)
	f := e.make(t, "ss5", 30*day, nil, map[string]any{"job": "5", "session": "sess-x"})
	v := safetyEval(e, f)
	check(t, v.Safe, "%s", debugVerdict(v))
	seen := number(markerEntry(e.Reg, f, e.A.Now())["session_exit_seen"])
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, ok && !exists(f), "%v %s", ok, detail)
	check(t, seen > 0, "gone session never recorded")
}

func TestHardlinksAreCountedOnce(t *testing.T) {
	e := newTestEnv(t)
	payload := bytes.Repeat([]byte("x"), 200000)
	f := e.make(t, "hl", 30*day, map[string][]byte{"a.bin": payload}, nil)
	must(t, os.Link(filepath.Join(f, "a.bin"), filepath.Join(f, "b.bin")))
	must(t, os.Link(filepath.Join(f, "a.bin"), filepath.Join(f, "c.bin")))
	v := safetyEval(e, f)
	solo := e.make(t, "solo", 30*day, map[string][]byte{"a.bin": payload}, nil)
	one := safetyEval(e, solo)
	check(t, v.Size != nil && one.Size != nil && *v.Size < *one.Size+8192, "hardlinks counted repeatedly: %v %v", v.Size, one.Size)
	// Allocation deduplication must still inspect each name against the deny-list.
	e.Cfg.DenyNames = append(e.Cfg.DenyNames, "c.bin")
	denied := safetyEval(e, f)
	check(t, !denied.Safe && strings.Contains(denied.Reason, "deny-listed"), "deduplicated hardlink escaped deny walk: %+v", denied)
}

func ignoreInMain(t *testing.T, main, pattern string) {
	t.Helper()
	safetyWrite(t, filepath.Join(main, ".git/info/exclude"), pattern+"\n")
}
func TestWorktreeWithIgnoredFilesNeedsIgnoredOk(t *testing.T) {
	e := newTestEnv(t)
	main, wt := linkedWorktree(t, e, "ig1")
	ignoreInMain(t, main, "data/")
	check(t, safetyEval(e, wt).Safe, "clean worktree refused")
	safetyWrite(t, filepath.Join(wt, "data/copy.bin"), "irreplaceable")
	v := safetyEval(e, wt)
	check(t, !v.Safe && strings.Contains(v.Reason, "contains ignored files; marker lacks ignored_ok"), "%s", debugVerdict(v))
	m, err := e.A.readMarker(wt)
	must(t, err)
	m.Extra["ignored_ok"] = true
	must(t, e.A.writeMarker(m))
	removalAge(t, wt, 30*day)
	check(t, safetyEval(e, wt).Safe, "owner attestation ignored: %s", debugVerdict(safetyEval(e, wt)))
}
func TestIgnoredFileAddedBeforeRemovalBlocks(t *testing.T) {
	e := newTestEnv(t)
	main, wt := linkedWorktree(t, e, "ig2")
	ignoreInMain(t, main, "data/")
	v := safetyEval(e, wt)
	check(t, v.Safe, "%s", debugVerdict(v))
	safetyWrite(t, filepath.Join(wt, "data/x"), "1")
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && strings.Contains(detail, "ignored_ok") && exists(wt), "%v %s", ok, detail)
}
func TestNestedLinkedWorktreeIgnoredFiles(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	ignoreInMain(t, main, "data/")
	f := e.make(t, "ig3", 30*day, nil, map[string]any{"kind": "mirror"})
	gitTest(t, main, "worktree", "add", "-q", "--detach", filepath.Join(f, "wt"))
	check(t, safetyEval(e, f).Safe, "clean nested worktree refused")
	safetyWrite(t, filepath.Join(f, "wt/data/x"), "1")
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "nested repo wt") && strings.Contains(v.Reason, "ignored_ok"), "%s", debugVerdict(v))
}
func TestJjSecondaryWorkspaceIgnoredFiles(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not installed")
	}
	e := newTestEnv(t)
	main := filepath.Join(e.Root, "jjmain")
	run := func(cwd string, args ...string) {
		t.Helper()
		r := e.A.Run(append([]string{"jj", "--config", `user.name="Fixture"`, "--config", `user.email="fixture@example.invalid"`}, args...), 60, cwd, nil)
		check(t, r.Err == nil && r.Code == 0, "jj %v: %v %s", args, r.Err, r.Stderr)
	}
	run("", "git", "init", main)
	safetyWrite(t, filepath.Join(main, ".gitignore"), "data/\n")
	safetyWrite(t, filepath.Join(main, "a"), "a")
	run(main, "commit", "-m", "init")
	ws := filepath.Join(e.Root, "jjws")
	run(main, "workspace", "add", ws)
	check(t, e.A.ignoredFiles(ws, "jj-secondary") == "", "clean secondary workspace has hidden data: %s", e.A.ignoredFiles(ws, "jj-secondary"))
	safetyWrite(t, filepath.Join(ws, "data/y"), "y")
	check(t, strings.Contains(e.A.ignoredFiles(ws, "jj-secondary"), "ignored files"), "ignored workspace data missed")
}

func TestIgnoredFileProbeFailuresKeepCheckout(t *testing.T) {
	for _, repo := range []string{"git-linked", "jj-secondary"} {
		for _, tc := range []struct {
			name   string
			result Result
		}{
			{"failure", Result{Code: 2}},
			{"timeout", Result{Timeout: true}},
			{"unavailable", Result{Err: os.ErrNotExist, Code: -1}},
		} {
			t.Run(repo+"-"+tc.name, func(t *testing.T) {
				e := newTestEnv(t)
				e.A.Run = func([]string, float64, string, []string) Result { return tc.result }
				check(t, e.A.ignoredFiles(e.Root, repo) != "", "failed ignored-file probe accepted")
			})
		}
	}
}

func TestIgnoredDirectorySymlinkNeedsIgnoredOk(t *testing.T) {
	for _, repo := range []string{"jj-secondary", "git-linked"} {
		t.Run(repo, func(t *testing.T) {
			e := newTestEnv(t)
			var folder string
			if repo == "git-linked" {
				main, wt := linkedWorktree(t, e, "ignored-link")
				ignoreInMain(t, main, "ignored-link")
				folder = wt
			} else {
				folder = e.make(t, "workspace", 30*day, nil, nil)
				safetyWrite(t, filepath.Join(folder, ".jj/repo"), "fixture")
				e.A.Run = func(args []string, _ float64, _ string, _ []string) Result {
					if contains(args, "list") {
						return Result{Stdout: "blob.bin\n"}
					}
					return Result{}
				}
			}
			v := safetyEval(e, folder)
			check(t, v.Safe, "clean fixture: %s", debugVerdict(v))
			target := filepath.Join(e.Root, "outside")
			safetyWrite(t, filepath.Join(target, "valuable.bin"), "irreplaceable")
			must(t, os.Symlink(target, filepath.Join(folder, "ignored-link")))
			v = safetyEval(e, folder)
			check(t, !v.Safe && strings.Contains(v.Reason, "ignored_ok"), "ignored directory link accepted: %s", debugVerdict(v))
			ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
			check(t, !ok && exists(folder), "ignored link removed: %v %s", ok, detail)
			m, err := e.A.readMarker(folder)
			must(t, err)
			m.Extra["ignored_ok"] = true
			must(t, e.A.writeMarker(m))
			removalAge(t, folder, 30*day)
			check(t, safetyEval(e, folder).Safe, "explicit ignored_ok refused")
			check(t, safetyRead(t, filepath.Join(target, "valuable.bin")) == "irreplaceable", "link target changed")
		})
	}
}

func TestIgnoredFileAddedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	main, wt := linkedWorktree(t, e, "ignored-during-move")
	ignoreInMain(t, main, "data/")
	m, err := e.A.readMarker(wt)
	must(t, err)
	m.MoveTo = filepath.Join(e.Root, "archive")
	must(t, e.A.writeMarker(m))
	removalAge(t, wt, 30*day)
	v := safetyEval(e, wt)
	check(t, v.Safe && v.Action == "move", "%s", debugVerdict(v))
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		safetyWrite(t, filepath.Join(wt, "data/valuable.bin"), "irreplaceable")
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && strings.Contains(detail, "ignored_ok") && exists(filepath.Join(wt, "data/valuable.bin")), "%v %s", ok, detail)
}

func TestProtectedFileIdentityBlocksHardlinkInMarkedTree(t *testing.T) {
	e := newTestEnv(t)
	protected := filepath.Join(e.Root, "protected.bin")
	safetyWrite(t, protected, "irreplaceable")
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, protected)
	f := e.make(t, "identity-alias", 30*day, nil, nil)
	must(t, os.Link(protected, filepath.Join(f, "alias.bin")))
	v := safetyEval(e, f)
	check(t, !v.Safe && strings.Contains(v.Reason, "contains deny-listed alias.bin"), "protected file identity was missed: %s", debugVerdict(v))
	check(t, safetyRead(t, protected) == "irreplaceable", "protected file modified")
}

func TestIgnoredWorkspacePrunesCanonicalMetadataNames(t *testing.T) {
	for _, name := range []string{".GIT", ".JJ", "nested/.GIT"} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "workspace", 30*day, map[string][]byte{name + "/internal": []byte("metadata")}, nil)
			e.A.Run = func([]string, float64, string, []string) Result { return Result{} }
			reason := e.A.ignoredFiles(f, "jj-secondary")
			check(t, (reason == "") == !strings.Contains(name, "/"), "metadata prune for %s: %s", name, reason)
		})
	}
}

func TestIgnoredWorkspaceSymlinksNeverFollowTargets(t *testing.T) {
	for _, targetKind := range []string{"directory", "file", "missing"} {
		for _, tracked := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s-tracked=%v", targetKind, tracked), func(t *testing.T) {
				e := newTestEnv(t)
				f := e.make(t, "workspace", 30*day, map[string][]byte{}, nil)
				target := filepath.Join(e.Root, "target")
				if targetKind == "directory" {
					must(t, os.Mkdir(target, 0755))
				} else if targetKind == "file" {
					safetyWrite(t, target, "irreplaceable")
				}
				must(t, os.Symlink(target, filepath.Join(f, ".JJ")))
				e.A.Run = func([]string, float64, string, []string) Result {
					if tracked {
						return Result{Stdout: ".JJ\n"}
					}
					return Result{}
				}
				realStat := e.A.StatAt
				e.A.StatAt = func(parent *os.File, name string, follow bool) (os.FileInfo, error) {
					check(t, !follow, "ignored check followed %s", name)
					return realStat(parent, name, follow)
				}
				reason := e.A.ignoredFiles(f, "jj-secondary")
				check(t, (reason == "") == tracked, "symlink tracked=%v: %s", tracked, reason)
			})
		}
	}
}

func TestNestedMarkerIndependentProtection(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]any
	}{
		{"hold", map[string]any{"holds": []any{map[string]any{"job": "busy"}}}},
		{"job", map[string]any{"job": "busy"}},
		{"session", map[string]any{"session": strconv.Itoa(os.Getpid())}},
		{"ttl", map[string]any{"ttl": "99d"}},
		{"move", map[string]any{"move_to": "archive"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			outer := e.make(t, "outer", 30*day, nil, nil)
			nested := e.make(t, "outer/deep/inner", 30*day, nil, tc.fields)
			v := safetyEval(e, outer)
			check(t, !v.Safe && strings.Contains(v.Reason, "nested marker") && exists(nested), "%s", debugVerdict(v))
		})
	}
}
func TestNestedMarkerCaseVariantsProtectAncestor(t *testing.T) {
	for _, name := range []string{".reclaimable", ".RECLAIMABLE", ".ReClAiMaBlE"} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			outer := e.make(t, "outer", 30*day, nil, nil)
			nested := e.make(t, "outer/a/b/inner", 30*day, nil, map[string]any{"holds": []any{map[string]any{"job": "busy"}}})
			must(t, os.Rename(filepath.Join(nested, markerName), filepath.Join(nested, name)))
			v := safetyEval(e, outer)
			check(t, !v.Safe && strings.Contains(v.Reason, "nested marker"), "%s", debugVerdict(v))
		})
	}
}
func TestExpiredNestedMarkerCanBeRemovedWithAncestor(t *testing.T) {
	e := newTestEnv(t)
	outer := e.make(t, "outer", 30*day, nil, nil)
	e.make(t, "outer/a/b/inner", 30*day, nil, nil)
	v := safetyEval(e, outer)
	check(t, v.Safe, "%s", debugVerdict(v))
}
func TestNestedMarkerUsesItsOwnHolderContext(t *testing.T) {
	e := newTestEnv(t)
	outer := e.make(t, "outer", 30*day, nil, nil)
	e.make(t, "outer/inner", 30*day, nil, map[string]any{"owner": "busy-owner"})
	e.Cfg.Holders = []map[string]any{{"command": []string{"sh", "-c", `if [ "$RECLAIMABLE_OWNER" = busy-owner ]; then echo busy; exit 0; fi; exit 1`}}}
	v := safetyEval(e, outer)
	check(t, !v.Safe && strings.Contains(v.Reason, "nested marker") && strings.Contains(v.Reason, "held"), "%s", debugVerdict(v))
}
func TestInvalidNestedMarkerFailsClosed(t *testing.T) {
	for _, problem := range []string{"malformed", "symlink", "directory"} {
		t.Run(problem, func(t *testing.T) {
			e := newTestEnv(t)
			outer := e.make(t, "outer", 30*day, nil, nil)
			nested := e.make(t, "outer/inner", 30*day, nil, nil)
			path := filepath.Join(nested, markerName)
			if problem == "malformed" {
				safetyWrite(t, path, "not json")
			} else {
				must(t, os.Remove(path))
				if problem == "symlink" {
					must(t, os.Symlink(filepath.Join(outer, markerName), path))
				} else {
					must(t, os.Mkdir(path, 0755))
				}
			}
			v := safetyEval(e, outer)
			check(t, !v.Safe && strings.Contains(v.Reason, "nested marker"), "%s", debugVerdict(v))
		})
	}
}
func TestNestedMarkerRecheckedBeforeAncestorRemoval(t *testing.T) {
	for _, change := range []string{"hold", "touch"} {
		t.Run(change, func(t *testing.T) {
			e := newTestEnv(t)
			outer := e.make(t, "outer", 30*day, nil, nil)
			nested := e.make(t, "outer/inner", 30*day, nil, nil)
			v := safetyEval(e, outer)
			check(t, v.Safe, "%s", debugVerdict(v))
			if change == "hold" {
				m, err := e.A.readMarker(nested)
				must(t, err)
				m.Holds = []map[string]any{{"job": "busy"}}
				must(t, e.A.writeMarker(m))
			} else {
				stamp := time.Now()
				must(t, os.Chtimes(filepath.Join(nested, markerName), stamp, stamp))
			}
			ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg, true)
			check(t, !ok && strings.Contains(detail, "nested marker") && exists(outer) && exists(nested), "%v %s", ok, detail)
		})
	}
}
func TestOuterIgnoredOkDoesNotOverrideNestedMarker(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	outer := e.make(t, "outer", 30*day, nil, map[string]any{"ignored_ok": true})
	nested := filepath.Join(outer, "wt")
	gitTest(t, main, "worktree", "add", "-q", "--detach", nested)
	safetyWrite(t, filepath.Join(nested, ".gitignore"), "private.bin\n")
	gitTest(t, nested, "add", ".gitignore")
	gitTest(t, nested, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ignore")
	gitTest(t, nested, "push", "-q", "origin", "HEAD:refs/heads/ignored")
	safetyWrite(t, filepath.Join(nested, "private.bin"), "keep")
	must(t, writeJSON(filepath.Join(nested, markerName), map[string]any{"owner": "t", "regenerate": "r", "ignored_ok": false}))
	removalAge(t, nested, 30*day)
	v := safetyEval(e, outer)
	check(t, !v.Safe && strings.Contains(v.Reason, "ignored_ok"), "%s", debugVerdict(v))
}
func TestNestedMarkerFinalCopyRecheckKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	outer, _ := makeMovable(t, e, "scratch1")
	nested := e.make(t, "scratch1/inner", 30*day, nil, nil)
	v := safetyEval(e, outer)
	check(t, v.Safe, "%s", debugVerdict(v))
	e.A.MoveAndVerify = func(string, string, []string, map[string]string) (bool, string) {
		m, err := e.A.readMarker(nested)
		must(t, err)
		m.Holds = []map[string]any{{"job": "busy"}}
		must(t, e.A.writeMarker(m))
		return true, "copied fixture"
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && strings.Contains(detail, "nested marker") && strings.Contains(detail, "held") && exists(outer) && exists(nested), "%v %s", ok, detail)
}
func TestNestedMarkerOwnDenyExactKeepsAncestor(t *testing.T) {
	e := newTestEnv(t)
	outer := e.make(t, "outer", 30*day, nil, nil)
	nested := e.make(t, "outer/inner", 30*day, nil, nil)
	e.Cfg.DenyExact = append(e.Cfg.DenyExact, nested)
	v := safetyEval(e, outer)
	check(t, !v.Safe && strings.Contains(v.Reason, "nested marker") && strings.Contains(v.Reason, "broad folder"), "%s", debugVerdict(v))
}
func TestNestedMarkerIgnoredOkIndependentAndInherited(t *testing.T) {
	e := newTestEnv(t)
	outer := e.make(t, "outer", 30*day, nil, map[string]any{"ignored_ok": true})
	nested := e.make(t, "outer/inner", 30*day, nil, map[string]any{"ignored_ok": false})
	repo := filepath.Join(nested, "wt")
	safetyWrite(t, filepath.Join(repo, ".git"), "gitdir: fixture")
	e.A.RepoState = func(path string) (string, string) {
		if path == repo {
			return "git-linked", ""
		}
		return "", ""
	}
	e.A.Run = func([]string, float64, string, []string) Result { return Result{Code: 0, Stdout: "!! private.bin\n"} }
	v := safetyEval(e, outer)
	check(t, !v.Safe, "nested own ignored_ok false overridden")
	must(t, os.Remove(filepath.Join(nested, markerName)))
	v = safetyEval(e, outer)
	check(t, v.Safe, "unmarked nested repo did not inherit ignored_ok: %s", debugVerdict(v))
}

func TestPinnedWalkDoesNotConsumeCallerDirectory(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "pinned-walk", 30*day, map[string][]byte{"sub/data.bin": []byte("safe")}, nil)
	root, err := openPathDir(f)
	must(t, err)
	defer root.Close()
	for i := 0; i < 2; i++ {
		w := e.A.walkAt(root, f, e.Cfg, true, 300)
		check(t, w.Problem == "" && w.Size != nil && w.Files >= 3, "pinned walk %d failed: %+v", i, w)
	}
	entries, err := root.ReadDir(-1)
	must(t, err)
	check(t, len(entries) == 2, "walk consumed caller directory offset: %v", entries)
}
