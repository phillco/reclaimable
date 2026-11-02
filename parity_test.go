package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

type paritySide struct {
	home, stub, python, binary, source string
	goSide                             bool
}
type parityStep struct {
	args    []string
	age     string
	cwd     string
	ignored bool
}

func TestCLIParity(t *testing.T) {
	python, err := exec.LookPath("python3")
	must(t, err)
	root, err := os.Getwd()
	must(t, err)
	build := t.TempDir()
	binary := filepath.Join(build, "reclaimable")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build parity binary: %v\n%s", err, out)
	}
	scenarios := []struct {
		name  string
		steps []parityStep
	}{
		{"empty", []parityStep{{args: []string{"ls", "-j"}}, {args: []string{"status"}}}},
		{"mark_touch", []parityStep{{args: []string{"mark", "$HOME/data/new", "-o", "tool", "-r", "rebuild", "-t", "3d"}}, {args: []string{"mark", "$HOME/data/new", "-o", "other"}}, {args: []string{"touch", "$HOME/data/new/.reclaimable"}}, {args: []string{"ls", "-qj"}}, {args: []string{"touch", "$HOME/data/missing"}}}},
		{"holds", []parityStep{{args: []string{"mark", "$HOME/data/held", "-o", "tool", "-r", "rerun"}}, {args: []string{"hold", "$HOME/data/held", "reader", "-p", "a/../b"}}, {args: []string{"hold", "$HOME/data/held", "reader", "-p", "b"}}, {args: []string{"hold", "$HOME/data/held", "reader", "-p", "c"}}, {args: []string{"ls", "-j"}}, {args: []string{"release", "$HOME/data/held", "reader", "-p", "b"}}, {args: []string{"release", "$HOME/data/held", "missing"}}, {args: []string{"release", "$HOME/data/held", "reader"}}}},
		{"deny", []parityStep{{args: []string{"mark", "$HOME/.ssh/keys", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/Documents", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/data/sensitive", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/data/Photo.photoslibrary/x", "-o", "tool", "-r", "r"}}}},
		{"eligibility", []parityStep{{args: []string{"mark", "$HOME/data/old", "-o", "tool", "-r", "r", "-t", "1d"}, age: "data/old"}, {args: []string{"mark", "$HOME/data/fresh", "-o", "tool", "-r", "r", "-t", "7d"}}, {args: []string{"ls", "-jS"}}, {args: []string{"ls", "-qj"}}, {args: []string{"ls"}}, {args: []string{"sweep", "-nSv"}}}},
		{"arming", []parityStep{{args: []string{"mark", "$HOME/data/old", "-o", "tool", "-r", "r", "-t", "1d"}, age: "data/old"}, {args: []string{"sweep", "-AS"}}, {args: []string{"arm"}}, {args: []string{"arm"}}, {args: []string{"sweep", "-S"}}, {args: []string{"sweep", "-nS"}}, {args: []string{"sweep", "-AS"}}, {args: []string{"arm", "-x"}}, {args: []string{"arm", "-x"}}}},
		{"move", []parityStep{{args: []string{"mark", "$HOME/data/scratch", "-o", "tool", "-r", "r", "-k", "scratch", "-t", "1d", "-m", "$HOME/archive"}, age: "data/scratch"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}, {args: []string{"ls", "-j"}}}},
		{"closed_job", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "closed", "-t", "1d"}, age: "data/job"}, {args: []string{"ls", "-jS"}}, {args: []string{"sweep", "-nS"}}}},
		{"open_job", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "open", "-t", "1d"}, age: "data/job"}, {args: []string{"ls", "-jS"}}, {args: []string{"sweep", "-nS"}}}},
		{"session_grace", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "closed", "-s", "session-z", "-t", "1d"}, age: "data/job"}, {args: []string{"ls", "-jS"}}, {args: []string{"sweep", "-nS"}}}},
		{"observed_close", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-k", "scratch", "-j", "observed"}, age: "data/job"}, {args: []string{"ls", "-jS"}}, {args: []string{"sweep", "-nS"}}}},
		{"unicode", []parityStep{{args: []string{"mark", "$HOME/data/café-🚀", "-o", "élève", "-r", "r"}}, {args: []string{"mark", "$HOME/data/保護λ", "-o", "tool", "-r", "r"}}, {args: []string{"ls", "-jqS"}}}},
		{"session_returns_before_remove", []parityStep{{args: []string{"mark", "$HOME/data/session", "-o", "tool", "-r", "r", "-j", "closed", "-s", "flip-live-before", "-t", "1d"}, age: "data/session"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}}},
		{"session_probe_fails_before_remove", []parityStep{{args: []string{"mark", "$HOME/data/session", "-o", "tool", "-r", "r", "-j", "closed", "-s", "flip-error-before", "-t", "1d"}, age: "data/session"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}}},
		{"session_returns_after_copy", []parityStep{{args: []string{"mark", "$HOME/data/session", "-o", "tool", "-r", "r", "-j", "closed", "-s", "flip-live-after", "-k", "scratch", "-m", "$HOME/archive", "-t", "1d"}, age: "data/session"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}}},
		{"fresh_job_before_move", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "flip-before", "-t", "1d"}, age: "data/job"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}, {args: []string{"ls", "-j"}}}},
		{"fresh_job_after_copy", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "flip-after", "-k", "scratch", "-m", "$HOME/archive", "-t", "1d"}, age: "data/job"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}, {args: []string{"ls", "-j"}}}},
		{"job_reclosed_before_remove", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "reclose-before", "-t", "1d"}, age: "data/job"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}}},
		{"job_reclosed_after_copy", []parityStep{{args: []string{"mark", "$HOME/data/job", "-o", "tool", "-r", "r", "-j", "reclose-after", "-k", "scratch", "-m", "$HOME/archive", "-t", "1d"}, age: "data/job"}, {args: []string{"arm"}}, {args: []string{"sweep", "-AS"}}}},
		{"case_and_normalisation", []parityStep{{args: []string{"mark", "$HOME/documents", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/data/Pics.PHOTOSLIBRARY", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/data/SENSITIVE", "-o", "tool", "-r", "r"}}, {args: []string{"mark", "$HOME/data/café", "-o", "tool", "-r", "r"}}}},
		{"invalid_marker", []parityStep{{args: []string{"ls", "-jS"}}}},
		{"ignored_worktree", []parityStep{{args: []string{"ls", "-jS"}}, {args: []string{"ls", "-jS"}, ignored: true}}},
		{"legacy_relative_registry", []parityStep{{args: []string{"ls", "-j"}}, {args: []string{"arm"}}, {args: []string{"sweep", "-A"}}}},
		{"relative_mark", []parityStep{{args: []string{"mark", "new", "-o", "tool", "-r", "r"}, cwd: "data"}, {args: []string{"ls", "-jq"}}}},
		{"relative_denied_ancestor", []parityStep{{args: []string{"mark", "cache", "-o", "tool", "-r", "r"}, cwd: "data/blocked"}}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			must(t, err)
			sides := []paritySide{{home: filepath.Join(base, "reference"), python: python, binary: binary, source: filepath.Join(root, "python/upstream/reclaimable")}, {home: filepath.Join(base, "native"), python: python, binary: binary, source: filepath.Join(root, "python/upstream/reclaimable"), goSide: true}}
			for i := range sides {
				s := &sides[i]
				s.stub = filepath.Join(s.home, "bin")
				must(t, os.MkdirAll(s.stub, 0755))
				must(t, os.MkdirAll(filepath.Join(s.home, "data"), 0755))
				must(t, os.MkdirAll(filepath.Join(s.home, "data/blocked"), 0755))
				must(t, os.MkdirAll(filepath.Join(s.home, ".config/reclaimable"), 0755))
				for _, name := range []string{"lsof", "pgrep"} {
					must(t, os.WriteFile(filepath.Join(s.stub, name), []byte("#!/bin/sh\nexit 1\n"), 0755))
				}
				must(t, os.WriteFile(filepath.Join(s.stub, "pgrep"), []byte(`#!/bin/sh
case "$3" in
 flip-live-before|flip-live-after|flip-error-before)
  counter="$HOME/session-probe-$3"
  n=0
  [ ! -f "$counter" ] || read -r n < "$counter"
  n=$((n+1))
  echo "$n" > "$counter"
  max=1
  [ "$3" != flip-live-after ] || max=2
  [ "$n" -gt "$max" ] || exit 1
  [ "$3" != flip-error-before ] || exit 2
  echo 4242
  exit 0;;
 *) exit 1;;
esac
`), 0755))
				helper := filepath.Join(s.stub, "jobdone")
				must(t, os.WriteFile(helper, []byte(`#!/bin/sh
case $1 in
 flip-before|flip-after|reclose-before|reclose-after)
  counter="$HOME/probe-$1"
  n=0
  [ ! -f "$counter" ] || read -r n < "$counter"
  n=$((n+1))
  echo "$n" > "$counter"
  max=1
  case $1 in *-after) max=2;; esac
  if [ "$n" -gt "$max" ]; then
   case $1 in reclose-*) echo 2000000000; exit 0;; *) exit 2;; esac
  fi
  echo 946684800
  exit 0;;
 closed) echo 946684800; exit 0;;
 observed) exit 0;;
 open) exit 1;;
 *) exit 2;;
esac
`), 0755))
				cfg := fmt.Sprintf("floor_gb = 0\ntarget_gb = 0\nroots = [%q]\ndeny_names = [\"sensitive\", \"保護[α-ω]\", \"café\"]\ndeny = [%q]\nsession_grace = \"3d\"\n[job_done]\ncommand = [%q, \"{job}\"]\n", filepath.Join(s.home, "data"), filepath.Join(s.home, "data/blocked"), helper)
				must(t, os.WriteFile(filepath.Join(s.home, ".config/reclaimable/config.toml"), []byte(cfg), 0600))
			}
			if sc.name == "ignored_worktree" {
				for _, side := range sides {
					env := &testEnv{Root: side.home}
					main := makeRepoWithRemote(t, env)
					must(t, os.WriteFile(filepath.Join(main, ".git/info/exclude"), []byte("hidden/\n"), 0644))
					wt := filepath.Join(side.home, "data/wt")
					gitTest(t, main, "worktree", "add", "-q", "--detach", wt)
					must(t, os.MkdirAll(filepath.Join(wt, "hidden"), 0755))
					must(t, os.WriteFile(filepath.Join(wt, "hidden/payload"), []byte("keep ignored bytes"), 0600))
					must(t, writeJSON(filepath.Join(wt, markerName), map[string]any{"owner": "tool", "regenerate": "rebuild", "kind": "worktree", "ttl": "1d"}))
					at := time.Unix(1600000000, 0)
					must(t, os.Chtimes(filepath.Join(wt, markerName), at, at))
				}
			}
			if sc.name == "invalid_marker" {
				for _, side := range sides {
					must(t, writeJSON(filepath.Join(side.home, "data/invalid", markerName), map[string]any{"owner": "tool"}))
				}
			}
			if sc.name == "legacy_relative_registry" {
				for _, side := range sides {
					folder := filepath.Join(side.home, "data/legacy")
					must(t, os.MkdirAll(folder, 0755))
					must(t, writeJSON(filepath.Join(folder, markerName), map[string]any{"owner": "tool", "regenerate": "r", "ttl": "0s"}))
					must(t, os.WriteFile(filepath.Join(folder, "payload"), []byte("keep"), 0600))
					must(t, writeJSON(filepath.Join(side.home, ".local/state/reclaimable/registry.json"), map[string]any{"markers": map[string]any{"data/legacy": map[string]any{"registered": 1}}, "last_scan": float64(time.Now().Unix()) + 3600}))
				}
			}
			for n, step := range sc.steps {
				results := make([]parityResult, 2)
				for i, s := range sides {
					if step.ignored {
						path := filepath.Join(s.home, "data/wt", markerName)
						data, err := readObject(path)
						must(t, err)
						data["ignored_ok"] = true
						must(t, writeJSON(path, data))
						at := time.Unix(1600000000, 0)
						must(t, os.Chtimes(path, at, at))
					}
					results[i] = s.run(t, step.args, step.cwd)
					if step.age != "" {
						folder := filepath.Join(s.home, step.age)
						must(t, os.WriteFile(filepath.Join(folder, "payload"), []byte("same disposable fixture bytes\n"), 0600))
						at := time.Unix(1600000000, 0)
						must(t, os.Chtimes(filepath.Join(folder, markerName), at, at))
					}
				}
				if !reflect.DeepEqual(results[0], results[1]) {
					t.Fatalf("step %d %v\nPython: %#v\nGo: %#v", n, step.args, results[0], results[1])
				}
				left := paritySnapshot(t, sides[0])
				right := paritySnapshot(t, sides[1])
				if !reflect.DeepEqual(left, right) {
					t.Fatalf("state after step %d %v\nPython: %s\nGo: %s", n, step.args, left, right)
				}
			}
		})
	}
}

type parityResult struct {
	Code     int
	Out, Err string
}

func (s paritySide) run(t *testing.T, args []string, cwd string) parityResult {
	t.Helper()
	args = append([]string(nil), args...)
	for i := range args {
		args[i] = strings.ReplaceAll(args[i], "$HOME", s.home)
	}
	var cmd *exec.Cmd
	if s.goSide {
		cmd = exec.Command(s.binary, args...)
	} else {
		cmd = exec.Command(s.python, append([]string{s.source}, args...)...)
	}
	cmd.Env = append(os.Environ(), "HOME="+s.home, "RECLAIMABLE_CONFIG="+filepath.Join(s.home, ".config/reclaimable/config.toml"), "PATH="+s.stub+":"+os.Getenv("PATH"))
	cmd.Dir = s.home
	if cwd != "" {
		cmd.Dir = filepath.Join(s.home, cwd)
	}
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return parityResult{code, parityText(out.String(), s.home), parityText(errout.String(), s.home)}
}

var freePattern = regexp.MustCompile(`free \d+(?:\.\d+)? (?:TB|GB|MB|KB|B)`)
var logStampPattern = regexp.MustCompile(`(?m)^\d{4}-\d\d-\d\d \d{1,2}:\d\d(?:am|pm) `)

func parityText(text, home string) string {
	text = strings.ReplaceAll(text, home, "$HOME")
	var raw any
	if json.Unmarshal([]byte(text), &raw) == nil {
		return parityJSON(raw)
	}
	text = freePattern.ReplaceAllString(text, "free <SPACE>")
	return logStampPattern.ReplaceAllString(text, "<TIME> ")
}
func parityJSON(raw any) string {
	var normalize func(any) any
	normalize = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				switch k {
				case "at", "age_s", "registered", "checked", "size_at", "last_scan", "last_used", "armed_at", "free":
					x[k] = "<VARIABLE>"
				case "closed_at", "first_closed_seen", "session_exit_seen":
					if number(v) > float64(time.Now().Unix()-60) {
						x[k] = "<VARIABLE>"
					}
				default:
					x[k] = normalize(v)
				}
			}
			return x
		case []any:
			for i, v := range x {
				x[i] = normalize(v)
			}
			return x
		default:
			return v
		}
	}
	b, _ := json.Marshal(normalize(raw))
	return string(b)
}
func paritySnapshot(t *testing.T, s paritySide) string {
	t.Helper()
	rows := []string{}
	for _, root := range []string{"data", "archive", ".local/state/reclaimable", ".local/log", ".config/reclaimable/armed"} {
		p := filepath.Join(s.home, root)
		if !exists(p) {
			continue
		}
		must(t, filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(d.Name(), ".lock") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(s.home, path)
			if err != nil {
				return err
			}
			// Move destinations contain the full source path below the host component.
			rel = strings.ReplaceAll(rel, s.home, "$HOME")
			rows = append(rows, rel+"="+parityText(string(b), s.home))
			return nil
		}))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}
