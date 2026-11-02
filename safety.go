package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (a *App) openFiles(folder string) string {
	if _, err := exec.LookPath("lsof"); err != nil {
		return "lsof unavailable"
	}
	r := a.Run([]string{"lsof", "-w", "-n", "-P", "-F", "pcn", "+D", folder}, 90, "", nil)
	if r.Timeout {
		return "lsof timed out"
	}
	if r.Err != nil || r.Code != 0 && r.Code != 1 {
		return fmt.Sprintf("lsof failed (%d)", r.Code)
	}
	procs := map[string]bool{}
	pid := "None"
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(line, "p") {
			pid = line[1:]
		} else if strings.HasPrefix(line, "c") {
			procs[line[1:]+"["+pid+"]"] = true
		}
	}
	if strings.TrimSpace(r.Stdout) != "" {
		names := sortedKeys(procs)
		if len(names) > 5 {
			names = names[:5]
		}
		if len(names) == 0 {
			names = []string{"?"}
		}
		return "open files: " + strings.Join(names, ", ")
	}
	return ""
}
func (a *App) processCwd(pid int) string {
	r := a.Run([]string{"lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn"}, 15, "", nil)
	if r.Err != nil || r.Timeout {
		return ""
	}
	for _, line := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(line, "n/") {
			return line[1:]
		}
	}
	return ""
}

var pathTokens = regexp.MustCompile(`[\s=:]+`)

func (a *App) pathsIn(value any) []string {
	var out []string
	switch v := value.(type) {
	case string:
		if strings.Contains(v, "/") || strings.HasPrefix(v, "~") {
			for _, token := range pathTokens.Split(v, -1) {
				if strings.HasPrefix(token, "/") || strings.HasPrefix(token, "~/") {
					out = append(out, a.expand(token))
				}
			}
		}
	case []any:
		for _, x := range v {
			out = append(out, a.pathsIn(x)...)
		}
	case []string:
		for _, x := range v {
			out = append(out, a.pathsIn(x)...)
		}
	}
	return out
}
func listDir(path string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil
	}
	return entries, err
}
func (a *App) expandDirs(pattern string) ([]string, error) {
	path := a.expand(pattern)
	found := []string{path}
	deadline := time.Now().Add(300 * time.Second)
	if strings.ContainsAny(path, "*?[") {
		parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
		found = []string{string(filepath.Separator)}
		for _, part := range parts {
			var next []string
			for _, base := range found {
				if time.Now().After(deadline) {
					return nil, fmt.Errorf("glob expansion timed out: %s", pattern)
				}
				entries, err := a.ListDir(base)
				if err != nil {
					return nil, err
				}
				for _, e := range entries {
					if pmatch(e.Name(), part) {
						next = append(next, filepath.Join(base, e.Name()))
					}
				}
			}
			found = next
		}
	}
	var out []string
	for _, p := range found {
		_, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func jsonFiles(path string) ([]string, error) {
	entries, err := listDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(fold(e.Name()), ".json") {
			out = append(out, filepath.Join(path, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}
func pathList(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	if s, ok := v.(string); ok {
		return []string{s}, true
	}
	return stringList(v)
}
func readObject(path string) (map[string]any, error) {
	v, err := loadJSON(path, nil)
	if err != nil {
		return nil, err
	}
	m := dict(v)
	if m == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	return m, nil
}
func validPID(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case string:
		n, e := strconv.Atoi(x)
		return n, e == nil
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
func (a *App) leaseHold(holder map[string]any, m *Marker) string {
	job := strings.TrimLeft(m.Job, "#")
	patterns, ok := pathList(holder["lease_dir"])
	if !ok {
		return "lease dir unreadable (invalid lease_dir)"
	}
	var dirs []string
	for _, pattern := range patterns {
		matches, err := a.expandDirs(pattern)
		if err != nil {
			return fmt.Sprintf("lease dir unreadable (%s)", err)
		}
		dirs = append(dirs, matches...)
	}
	claims, ok := pathList(holder["claim_dir"])
	if !ok {
		return "claim dir unreadable (invalid claim_dir)"
	}
	for i := range claims {
		claims[i] = a.expand(claims[i])
	}
	for _, d := range dirs {
		files, err := jsonFiles(d)
		if err != nil {
			return fmt.Sprintf("lease dir unreadable (%s)", err)
		}
		for _, path := range files {
			lease, err := readObject(path)
			if err != nil {
				return "unreadable lease " + filepath.Base(path)
			}
			pid, ok := validPID(lease["pid"])
			if !ok {
				return "unreadable lease " + filepath.Base(path)
			}
			if !pidAlive(pid) {
				continue
			}
			leaseJob := textValue(lease["job"])
			if !truth(lease["job"]) {
				leaseJob = "?"
			}
			name := "lease " + filepath.Base(path) + " (" + leaseJob + ")"
			if job != "" && (job == textValue(lease["job"]) || job == textValue(lease["issue"])) {
				return name + " is this job"
			}
			refs := append(a.pathsIn(lease["log"]), a.pathsIn(lease["what"])...)
			if claim := lease["claim_id"]; truth(claim) {
				for _, dir := range claims {
					recPath := filepath.Join(dir, textValue(claim)+".json")
					if _, err := os.Stat(recPath); errors.Is(err, os.ErrNotExist) {
						continue
					}
					rec, err := readObject(recPath)
					if err != nil {
						return "unreadable claim record " + filepath.Base(recPath)
					}
					refs = append(refs, a.pathsIn(rec["cwd"])...)
					refs = append(refs, a.pathsIn(rec["command"])...)
				}
			}
			if cwd := a.ProcessCwd(pid); cwd != "" {
				refs = append(refs, cwd)
			}
			for _, ref := range refs {
				if related(ref, m.Folder) {
					return name + " uses " + ref
				}
			}
		}
	}
	for _, dir := range claims {
		files, err := jsonFiles(dir)
		if err != nil {
			return fmt.Sprintf("claim dir unreadable (%s)", err)
		}
		for _, path := range files {
			rec, err := readObject(path)
			if err != nil {
				return "unreadable claim record " + filepath.Base(path)
			}
			state := textValue(rec["state"])
			if state != "starting" && state != "running" {
				continue
			}
			if state == "running" && truth(rec["pid"]) {
				pid, ok := validPID(rec["pid"])
				if !ok {
					return "unreadable claim record " + filepath.Base(path)
				}
				if !pidAlive(pid) {
					continue
				}
			}
			refs := append(a.pathsIn(rec["cwd"]), a.pathsIn(rec["command"])...)
			for _, ref := range refs {
				if related(ref, m.Folder) {
					return "claim " + strings.TrimSuffix(filepath.Base(path), ".json") + " uses " + ref
				}
			}
		}
	}
	return ""
}
func (a *App) fill(arg string, values map[string]string) string {
	if strings.HasPrefix(arg, "~/") {
		arg = a.expand(arg)
	}
	p, err := filepath.Abs(a.ConfigFile)
	if err != nil {
		p = a.ConfigFile
	}
	if real, e := filepath.EvalSymlinks(p); e == nil {
		p = real
	}
	arg = strings.ReplaceAll(arg, "{config_dir}", filepath.Dir(p))
	for k, v := range values {
		arg = strings.ReplaceAll(arg, "{"+k+"}", v)
	}
	return arg
}
func withEnv(values map[string]string) []string {
	env := os.Environ()
	for k, v := range values {
		key := "RECLAIMABLE_" + strings.ToUpper(k) + "="
		var next []string
		for _, s := range env {
			if !strings.HasPrefix(s, key) {
				next = append(next, s)
			}
		}
		env = append(next, key+v)
	}
	return env
}
func (a *App) filledCommand(raw any, values map[string]string) ([]string, bool) {
	cmd, ok := stringList(raw)
	if !ok || len(cmd) == 0 {
		return nil, false
	}
	out := make([]string, len(cmd))
	for i, s := range cmd {
		out[i] = a.fill(s, values)
	}
	return out, true
}
func timeoutValue(m map[string]any, fallback float64) float64 {
	if v, ok := m["timeout"]; ok {
		n := number(v)
		if n < 0 {
			return 0
		}
		return n
	}
	return fallback
}
func shortText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func firstLine(s string) string { return strings.Split(s, "\n")[0] }
func (a *App) commandHold(holder map[string]any, m *Marker) string {
	values := map[string]string{"folder": m.Folder, "path": m.Folder, "job": m.Job, "owner": m.Owner, "session": m.Session, "kind": m.effectiveKind()}
	cmd, ok := a.filledCommand(holder["command"], values)
	if !ok {
		return "holder failed to run (invalid command)"
	}
	name := textValue(holder["name"])
	if name == "" {
		name = filepath.Base(cmd[0])
	}
	r := a.Run(cmd, timeoutValue(holder, 60), "", withEnv(values))
	if r.Timeout {
		return "holder " + name + " timed out"
	}
	if r.Err != nil {
		return fmt.Sprintf("holder %s failed to run (%s)", name, r.Err)
	}
	if r.Code == 1 {
		return ""
	}
	if r.Code == 0 {
		detail := shortText(firstLine(strings.TrimSpace(r.Stdout)), 100)
		if detail != "" {
			return "holder " + name + ": " + detail
		}
		return "holder " + name
	}
	return fmt.Sprintf("holder %s exited %d (treated as held)", name, r.Code)
}
func (a *App) holderHold(m *Marker, cfg *Config) string {
	for _, holder := range cfg.Holders {
		reason := ""
		if _, ok := holder["command"]; ok {
			reason = a.commandHold(holder, m)
		} else {
			reason = a.leaseHold(holder, m)
		}
		if reason != "" {
			return reason
		}
	}
	return ""
}

var epochPattern = regexp.MustCompile(`^\d+(\.\d+)?$`)

func parseClosedAt(s string) *float64 {
	s = strings.TrimSpace(s)
	if epochPattern.MatchString(s) {
		n, e := strconv.ParseFloat(s, 64)
		if e == nil {
			return &n
		}
		return nil
	}
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	if e != nil {
		return nil
	}
	n := float64(t.Unix())
	return &n
}
func (a *App) jobClosed(job string, cfg *Config, reg map[string]any) (*bool, *float64, string) {
	return a.jobClosedChecked(job, cfg, reg, true)
}

// Final removal checks must observe the scheduler again even when evaluation
// recently cached a positive close result.
func (a *App) jobClosedFresh(job string, cfg *Config, reg map[string]any) (*bool, *float64, string) {
	return a.jobClosedChecked(job, cfg, reg, false)
}

func (a *App) jobClosedChecked(job string, cfg *Config, reg map[string]any, useCache bool) (*bool, *float64, string) {
	if len(cfg.JobDone) == 0 {
		return nil, nil, "no job_done command configured"
	}
	cache := mapEntry(reg, "jobs")
	hit := dict(cache[job])
	if useCache && truth(hit["closed"]) && a.Now()-number(hit["checked"]) < 3600 {
		closed := true
		var at *float64
		if hit["closed_at"] != nil {
			n := number(hit["closed_at"])
			at = &n
		}
		return &closed, at, "closed"
	}
	firstSeen := number(hit["first_closed_seen"])
	cmd, ok := a.filledCommand(cfg.JobDone["command"], map[string]string{"job": job})
	if !ok {
		delete(cache, job)
		return nil, nil, "job_done failed to run (invalid command)"
	}
	r := a.Run(cmd, timeoutValue(cfg.JobDone, 30), "", withEnv(map[string]string{"job": job}))
	if r.Timeout {
		delete(cache, job)
		return nil, nil, "job_done timed out"
	}
	if r.Err != nil {
		delete(cache, job)
		return nil, nil, fmt.Sprintf("job_done failed to run (%s)", r.Err)
	}
	if r.Code != 0 && r.Code != 1 {
		delete(cache, job)
		return nil, nil, fmt.Sprintf("job_done exited %d", r.Code)
	}
	closed := r.Code == 0
	var at *float64
	if closed && strings.TrimSpace(r.Stdout) != "" {
		at = parseClosedAt(firstLine(r.Stdout))
	}
	record := map[string]any{"closed": closed, "closed_at": nil, "checked": a.Now()}
	if closed && at == nil {
		if firstSeen == 0 {
			firstSeen = a.Now()
		}
		record["first_closed_seen"] = firstSeen
		at = &firstSeen
	}
	if at != nil {
		record["closed_at"] = *at
	}
	cache[job] = record
	if closed {
		return &closed, at, "closed"
	}
	return &closed, at, "open"
}

var digitsPattern = regexp.MustCompile(`^\d+$`)

func (a *App) sessionRunning(session string) string {
	if digitsPattern.MatchString(session) {
		pid, err := strconv.Atoi(session)
		if err != nil {
			return "unknown"
		}
		if pidAlive(pid) {
			return "alive"
		}
		return "gone"
	}
	if _, err := exec.LookPath("pgrep"); err != nil {
		return "unknown"
	}
	r := a.Run([]string{"pgrep", "-f", "--", session}, 15, "", nil)
	if r.Err != nil || r.Timeout || r.Code != 0 && r.Code != 1 {
		return "unknown"
	}
	for _, s := range strings.Fields(r.Stdout) {
		pid, e := strconv.Atoi(s)
		if e == nil && pid != os.Getpid() {
			return "alive"
		}
	}
	return "no-match"
}
func changes(output string, porcelain bool) []string {
	var out []string
	for _, line := range strings.Split(output, "\n") {
		path := ""
		if porcelain {
			if len(line) >= 3 {
				path = line[3:]
			}
		} else {
			path = strings.TrimSpace(line)
		}
		if path != "" && path != markerName {
			out = append(out, path)
		}
	}
	return out
}
func unavailable(r Result) bool { return r.Err != nil || r.Timeout }
func (a *App) repoState(folder string) (string, string) {
	jj, git := filepath.Join(folder, ".jj"), filepath.Join(folder, ".git")
	if isDir(jj) {
		kind := "jj-primary"
		if isFile(filepath.Join(jj, "repo")) {
			kind = "jj-secondary"
		}
		d := a.Run([]string{"jj", "-R", folder, "--ignore-working-copy", "diff", "--name-only"}, 60, "", nil)
		if unavailable(d) {
			return kind, "jj unavailable or timed out"
		}
		if d.Code != 0 {
			return kind, "jj diff failed"
		}
		s := a.Run([]string{"jj", "-R", folder, "diff", "--name-only"}, 120, "", nil)
		if unavailable(s) {
			return kind, "jj unavailable or timed out"
		}
		if s.Code != 0 || len(changes(d.Stdout, false)) > 0 || len(changes(s.Stdout, false)) > 0 {
			return kind, "dirty (jj diff non-empty)"
		}
		u := a.Run([]string{"jj", "-R", folder, "--ignore-working-copy", "log", "--no-graph", "-T", `commit_id ++ "\n"`, "-r", "(::@ ~ ::remote_bookmarks()) ~ empty() ~ root()"}, 60, "", nil)
		if unavailable(u) {
			return kind, "jj unavailable or timed out"
		}
		if u.Code != 0 {
			return kind, "jj log failed"
		}
		if strings.TrimSpace(u.Stdout) != "" {
			return kind, "unpushed jj commits"
		}
		return kind, ""
	}
	if exists(git) {
		kind := "git-primary"
		if isFile(git) {
			kind = "git-linked"
		}
		st := a.Run([]string{"git", "-C", folder, "status", "--porcelain"}, 120, "", nil)
		if unavailable(st) {
			return kind, "git unavailable or timed out"
		}
		if st.Code != 0 {
			return kind, "git status failed"
		}
		if len(changes(st.Stdout, true)) > 0 {
			return kind, "dirty (git status non-empty)"
		}
		un := a.Run([]string{"git", "-C", folder, "rev-list", "--count", "HEAD", "--not", "--remotes"}, 60, "", nil)
		if unavailable(un) {
			return kind, "git unavailable or timed out"
		}
		if un.Code != 0 {
			return kind, "git rev-list failed"
		}
		if strings.TrimSpace(un.Stdout) != "0" {
			return kind, strings.TrimSpace(un.Stdout) + " unpushed commits"
		}
		return kind, ""
	}
	return "", ""
}

// ignoredFiles checks data omitted by repository cleanliness commands. Only the
// owner's explicit ignored_ok boolean attestation may bypass this check.
func (a *App) ignoredFiles(folder, repo string) string {
	if strings.HasPrefix(repo, "git") {
		r := a.Run([]string{"git", "-C", folder, "status", "--porcelain", "--ignored"}, 120, "", nil)
		if unavailable(r) {
			return "ignored-file check unavailable"
		}
		if r.Code != 0 {
			return "git status --ignored failed"
		}
		for _, line := range strings.Split(r.Stdout, "\n") {
			if strings.HasPrefix(line, "!! ") && strings.TrimRight(line[3:], "/") != markerName {
				return "contains ignored files; marker lacks ignored_ok (" + line[3:] + ")"
			}
		}
		return ""
	}
	r := a.Run([]string{"jj", "--ignore-working-copy", "file", "list"}, 120, folder, nil)
	if unavailable(r) {
		return "ignored-file check unavailable"
	}
	if r.Code != 0 {
		return "jj file list failed"
	}
	tracked := map[string]bool{}
	for _, line := range strings.Split(r.Stdout, "\n") {
		tracked[line] = true
	}
	root, err := openPathDir(folder)
	if err != nil {
		return "ignored-file check unavailable"
	}
	defer root.Close()
	rootInfo, err := root.Stat()
	if err != nil {
		return "ignored-file check unavailable"
	}
	hidden := ""
	var descend func(*os.File, string) error
	descend = func(dir *os.File, relative string) error {
		entries, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			name := entry.Name()
			rel := filepath.Join(relative, name)
			st, err := a.StatAt(dir, name, false)
			if err != nil {
				return err
			}
			if st.IsDir() {
				if relative == "" && (name == ".jj" || name == ".git") {
					continue
				}
				if device(st) != device(rootInfo) {
					return fmt.Errorf("another filesystem")
				}
				a.fsBefore("ignored-descend", filepath.Join(folder, relative), name)
				next, err := openAt(dir, name, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_RDONLY, 0)
				if err != nil {
					return err
				}
				opened, err := next.Stat()
				if err != nil {
					next.Close()
					return err
				}
				if !sameIdentity(st, opened) {
					next.Close()
					return fmt.Errorf("directory replaced")
				}
				err = descend(next, rel)
				closeErr := next.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
				if hidden != "" {
					return nil
				}
				continue
			}
			if st.Mode()&os.ModeSymlink != 0 {
				// Classify directory links as os.walk does, while never entering them.
				if target, err := a.StatAt(dir, name, true); err == nil && target.IsDir() {
					continue
				}
			}
			if rel != markerName && !tracked[rel] {
				hidden = "contains ignored files; marker lacks ignored_ok (" + rel + ")"
				return nil
			}
		}
		return nil
	}
	if err := descend(root, ""); err != nil {
		return "ignored-file check unavailable"
	}
	return hidden
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (a *App) walk(folder string, cfg *Config, checkNames bool, limit float64) (w Walk) {
	folder = a.expand(folder)
	inspected, err := a.Lstat(folder)
	if err != nil {
		w.Problem = fmt.Sprintf("unreadable %s: %s", folder, err)
		return w
	}
	if !inspected.IsDir() {
		w.Problem = "unreadable " + folder + ": not a real directory"
		return w
	}
	root, err := openPathDir(folder)
	if err != nil {
		w.Problem = fmt.Sprintf("unreadable %s: %s", folder, err)
		return w
	}
	defer root.Close()
	opened, err := root.Stat()
	if err != nil {
		w.Problem = fmt.Sprintf("unreadable %s: %s", folder, err)
		return w
	}
	if device(opened) != device(inspected) || inode(opened) != inode(inspected) {
		w.Problem = "folder replaced during size walk"
		return w
	}
	return a.walkAt(root, folder, cfg, checkNames, limit)
}

// walkAt opens a fresh directory description so reading never consumes the
// caller's pinned root descriptor or changes its directory enumeration offset.
func (a *App) walkAt(root *os.File, folder string, cfg *Config, checkNames bool, limit float64) (w Walk) {
	folder = a.expand(folder)
	repos := map[string]bool{}
	w.MarkerFolders = map[string]FileIdentity{}
	defer func() { w.Repos = sortedKeys(repos) }()
	scanRoot, err := openAt(root, ".", syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_RDONLY, 0)
	if err != nil {
		w.Problem = fmt.Sprintf("unreadable %s: %s", folder, err)
		return w
	}
	defer scanRoot.Close()
	opened, err := scanRoot.Stat()
	if err != nil {
		w.Problem = fmt.Sprintf("unreadable %s: %s", folder, err)
		return w
	}
	if !opened.IsDir() {
		w.Problem = "unreadable " + folder + ": not a real directory"
		return w
	}
	dev := device(opened)
	deadline := time.Now().Add(time.Duration(limit * float64(time.Second)))
	protected, err := a.protectedIdentitiesChecked(cfg)
	if err != nil {
		w.Problem = fmt.Sprintf("deny-list unreadable (%s)", err)
		return w
	}
	seen := map[FileIdentity]bool{}
	patterns := make([]string, len(cfg.DenyPaths))
	for i, p := range cfg.DenyPaths {
		patterns[i] = a.expand(p)
	}
	size := int64(0)
	type childDir struct {
		name, path string
		info       os.FileInfo
	}
	var descend func(*os.File, string) bool
	descend = func(dir *os.File, logical string) bool {
		if time.Now().After(deadline) {
			w.Problem = "size walk timed out"
			return false
		}
		entries, err := dir.ReadDir(-1)
		if err != nil {
			w.Problem = fmt.Sprintf("unreadable %s: %s", logical, err)
			return false
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		children := []childDir{}
		for _, e := range entries {
			p := filepath.Join(logical, e.Name())
			st, err := a.StatAt(dir, e.Name(), false)
			if err != nil {
				w.Problem = fmt.Sprintf("unreadable %s: %s", p, err)
				return false
			}
			w.Files++
			hardlinked := false
			if stat, ok := st.Sys().(*syscall.Stat_t); ok {
				hardlinked = stat.Nlink > 1 && !st.IsDir()
			}
			if hardlinked {
				key := FileIdentity{device(st), inode(st)}
				if !seen[key] {
					seen[key] = true
					size += allocated(st)
				}
			} else {
				size += allocated(st)
			}
			rel, err := filepath.Rel(folder, p)
			if err != nil {
				w.Problem = "unreadable " + p + ": " + err.Error()
				return false
			}
			absolute, err := filepath.Abs(p)
			if err != nil {
				w.Problem = "unreadable " + p + ": " + err.Error()
				return false
			}
			if fold(e.Name()) == fold(markerName) && a.pathKey(logical) != a.pathKey(folder) {
				if !st.Mode().IsRegular() {
					w.Problem = "invalid nested marker " + rel
					return false
				}
				parentInfo, err := dir.Stat()
				if err != nil {
					w.Problem = fmt.Sprintf("unreadable %s: %s", logical, err)
					return false
				}
				w.Markers = append(w.Markers, p)
				w.MarkerFolders[p] = FileIdentity{device(parentInfo), inode(parentInfo)}
			}
			hitPath := false
			for _, pattern := range patterns {
				if a.pathMatch(p, pattern) || a.pathMatch(absolute, pattern) {
					hitPath = true
					break
				}
			}
			if hitPath || protected[FileIdentity{device(st), inode(st)}] {
				w.Problem = "contains deny-listed " + rel
				return false
			}
			if checkNames && denyNameHit(strings.Split(rel, string(filepath.Separator)), cfg) != "" {
				w.Problem = "contains deny-listed " + rel
				return false
			}
			if (fold(e.Name()) == ".git" || fold(e.Name()) == ".jj") && a.pathKey(logical) != a.pathKey(folder) {
				repos[logical] = true
			}
			if st.IsDir() {
				if device(st) == dev {
					children = append(children, childDir{e.Name(), p, st})
				} else {
					w.Crossed = append(w.Crossed, p)
				}
			}
		}
		for i := len(children) - 1; i >= 0; i-- {
			child := children[i]
			if a.FSBefore != nil {
				a.FSBefore("walk-descend", logical, child.name)
			}
			next, err := openAt(dir, child.name, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_RDONLY, 0)
			if err != nil {
				w.Problem = fmt.Sprintf("unreadable %s: %s", child.path, err)
				return false
			}
			actual, err := next.Stat()
			if err != nil {
				next.Close()
				w.Problem = fmt.Sprintf("unreadable %s: %s", child.path, err)
				return false
			}
			if !actual.IsDir() || device(actual) != dev || device(actual) != device(child.info) || inode(actual) != inode(child.info) {
				next.Close()
				w.Problem = "directory replaced during size walk: " + child.path
				return false
			}
			ok := descend(next, child.path)
			closeErr := next.Close()
			if !ok {
				return false
			}
			if closeErr != nil {
				w.Problem = fmt.Sprintf("unreadable %s: %s", child.path, closeErr)
				return false
			}
		}
		return true
	}
	if !descend(scanRoot, folder) {
		return w
	}
	w.Size = &size
	return w
}

// sessionProblem is shared by evaluation and both final removal boundaries.
// Every non-conclusive probe clears the recorded exit observation.
func (a *App) sessionProblem(m *Marker, cfg *Config, entry map[string]any, closedAt *float64) string {
	if m.Session == "" {
		return ""
	}
	label := shortText(m.Session, 12)
	running := a.SessionRunning(m.Session)
	if running == "no-match" && cfg.SessionGrace != nil && m.Job != "" && !digitsPattern.MatchString(m.Session) {
		if closedAt == nil || *closedAt == 0 {
			delete(entry, "session_exit_seen")
			return "session " + label + " unknown and job close time unavailable"
		}
		ready := *closedAt + *cfg.SessionGrace
		if a.Now() < ready {
			delete(entry, "session_exit_seen")
			return "session " + label + " within grace (job closed " + humanAge(a.Now()-*closedAt) + " ago, grace " + humanAge(*cfg.SessionGrace) + ")"
		}
		running = "gone"
		if _, ok := entry["session_exit_seen"]; !ok {
			entry["session_exit_seen"] = ready
		}
	}
	if running == "unknown" || running == "no-match" || running == "" {
		delete(entry, "session_exit_seen")
		return "session " + label + " state unknown"
	}
	if running == "alive" {
		delete(entry, "session_exit_seen")
		return "session " + label + " still running"
	}
	if _, ok := entry["session_exit_seen"]; !ok {
		entry["session_exit_seen"] = a.Now()
	}
	return ""
}

func (a *App) treeProblem(folder string, m *Marker, cfg *Config, w Walk) (string, string) {
	if w.Problem != "" {
		return w.Problem, ""
	}
	if len(w.Crossed) > 0 {
		rel, _ := filepath.Rel(folder, w.Crossed[0])
		return "contains another filesystem at " + rel, ""
	}
	nestedMarkers := map[string]*Marker{}
	for _, markerPath := range w.Markers {
		rel, _ := filepath.Rel(folder, markerPath)
		label := "nested marker " + rel
		nestedFolder := filepath.Dir(markerPath)
		key := a.pathKey(nestedFolder)
		if _, ok := nestedMarkers[key]; ok {
			return label + ": ambiguous marker spelling", ""
		}
		parent, err := openPathDir(nestedFolder)
		if err != nil {
			return label + ": unreadable or invalid (" + err.Error() + ")", ""
		}
		parentInfo, err := parent.Stat()
		expected, known := w.MarkerFolders[markerPath]
		if err != nil || !known || expected != (FileIdentity{device(parentInfo), inode(parentInfo)}) {
			parent.Close()
			return label + ": unreadable or invalid (marker directory changed since walk)", ""
		}
		nested, err := a.readMarkerAt(parent, nestedFolder, filepath.Base(markerPath))
		closeErr := parent.Close()
		if err != nil {
			return label + ": unreadable or invalid (" + err.Error() + ")", ""
		}
		if closeErr != nil {
			return label + ": unreadable or invalid (" + closeErr.Error() + ")", ""
		}
		if len(nested.Holds) > 0 {
			return label + ": held", ""
		}
		if nested.Job != "" || nested.Session != "" {
			return label + ": job/session requires independent removal", ""
		}
		ttl, err := parseTTL(a.markerTTL(nested))
		if err != nil {
			return label + ": unreadable or invalid (" + err.Error() + ")", ""
		}
		if a.Now()-nested.Mtime < ttl {
			return label + ": not expired", ""
		}
		if nested.MoveTo != "" || (cfg.MoveRoot != "" && nested.effectiveKind() != "cache") {
			return label + ": move requires independent removal", ""
		}
		if denied := a.denyReason(nested.Folder, cfg); denied != "" {
			return label + ": refused: " + denied, ""
		}
		if held := a.holderHold(nested, cfg); held != "" {
			return label + ": held: " + held, ""
		}
		if problem, _ := a.treeProblem(nested.Folder, nested, cfg, Walk{}); problem != "" {
			return label + ": " + problem, ""
		}
		nestedMarkers[key] = nested
	}

	repo, problem := a.RepoState(folder)
	if problem != "" {
		return "worktree " + problem, repo
	}
	if repo == "git-primary" || repo == "jj-primary" {
		return repo + " repository (only linked worktrees / secondary workspaces are removable)", repo
	}
	if m.effectiveKind() == "worktree" && repo == "" {
		return "kind worktree but no .git/.jj found", repo
	}
	ignoredOK, _ := m.Extra["ignored_ok"].(bool)
	if repo != "" && !ignoredOK {
		if hidden := a.ignoredFiles(folder, repo); hidden != "" {
			return hidden, repo
		}
	}
	for i, nested := range w.Repos {
		if i >= 20 {
			break
		}
		kind, problem := a.RepoState(nested)
		rel, _ := filepath.Rel(folder, nested)
		if problem != "" {
			return "nested repo " + rel + " " + problem, repo
		}
		nestedIgnoredOK := ignoredOK
		for _, ancestor := range ancestors(nested) {
			if ownMarker := nestedMarkers[a.pathKey(ancestor)]; ownMarker != nil {
				nestedIgnoredOK, _ = ownMarker.Extra["ignored_ok"].(bool)
				break
			}
		}
		if (kind == "git-linked" || kind == "jj-secondary") && !nestedIgnoredOK {
			if hidden := a.ignoredFiles(nested, kind); hidden != "" {
				return "nested repo " + rel + " " + hidden, repo
			}
		}
		if kind == "git-primary" || kind == "jj-primary" {
			return "nested " + kind + " repository " + rel + " (only linked worktrees / secondary workspaces are removable)", repo
		}
	}
	if len(w.Repos) > 20 {
		return fmt.Sprintf("%d nested repos (too many to verify)", len(w.Repos)), repo
	}
	return "", repo
}
func (a *App) evaluate(folder string, cfg *Config, reg map[string]any, deep bool) *Verdict {
	folder = a.expand(folder)
	v := &Verdict{Folder: folder, Action: "keep"}
	m, err := a.readMarker(folder)
	if err != nil {
		v.Reason = "bad marker: " + err.Error()
		return v
	}
	v.Marker = m
	v.DirectoryID = m.DirectoryID
	v.LastUsed = m.Mtime
	entry := markerEntry(reg, folder, a.Now())
	if n, ok := entry["size"]; ok {
		n := int64(number(n))
		v.Size = &n
	}
	if reason := a.denyReason(folder, cfg); reason != "" {
		v.Reason = "refused: " + reason
		return v
	}
	v.TTLS, err = parseTTL(a.markerTTL(m))
	if err != nil {
		v.Reason = "bad marker: " + err.Error()
		return v
	}
	start := m.Mtime
	if len(m.Holds) > 0 {
		names := make([]string, len(m.Holds))
		for i, h := range m.Holds {
			names[i] = textValue(h["job"])
			if h["job"] == nil {
				names[i] = "None"
			}
		}
		v.Reason = "held by " + strings.Join(names, ", ")
		return v
	}
	var closedAt *float64
	if m.Job != "" {
		closed, at, detail := a.jobClosed(m.Job, cfg, reg)
		closedAt = at
		if closed == nil || !*closed {
			if closed == nil {
				detail = "state unknown: " + detail
			}
			v.Reason = "job " + m.Job + " " + detail
			return v
		}
		if at != nil {
			start = max(start, *at)
		}
	}
	if m.Session != "" {
		if reason := a.sessionProblem(m, cfg, entry, closedAt); reason != "" {
			v.Reason = reason
			return v
		}
		start = max(start, number(entry["session_exit_seen"]))
	}

	v.ClockStart = start
	v.Expired = a.Now()-start >= v.TTLS
	if !deep {
		v.Safe = true
		if v.Expired {
			v.Reason = "expired (shallow)"
		} else {
			v.Reason = "fresh, expires in " + humanAge(start+v.TTLS-a.Now())
		}
		return v
	}
	w := a.walk(folder, cfg, true, 300)
	if w.Size != nil {
		v.Size = w.Size
		entry["size"] = *w.Size
		entry["size_at"] = a.Now()
	}
	reason, repo := a.treeProblem(folder, m, cfg, w)
	v.Repo = repo
	if reason != "" {
		v.Reason = reason
		return v
	}
	if hold := a.holderHold(m, cfg); hold != "" {
		v.Reason = "held: " + hold
		return v
	}
	if busy := a.OpenFiles(folder); busy != "" {
		v.Reason = busy
		return v
	}
	v.Safe = true
	if v.Expired {
		v.Reason = "expired (" + humanAge(a.Now()-start) + " > " + a.markerTTL(m) + ")"
	} else {
		v.Reason = "safe, expires in " + humanAge(start+v.TTLS-a.Now())
	}
	dest := m.MoveTo
	if dest == "" && m.effectiveKind() != "cache" {
		dest = cfg.MoveRoot
	}
	if dest != "" {
		v.Action = "move"
		v.Dest = dest
	} else {
		v.Action = "delete"
	}
	return v
}
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func (a *App) row(v *Verdict) map[string]any {
	var owner, kind, job, ttl, age, size any
	if m := v.Marker; m != nil {
		owner = m.Owner
		kind = m.effectiveKind()
		job = nullableText(m.Job)
		if m.JobPresent {
			job = m.Job
		}
		ttl = a.markerTTL(m)
	}
	if v.LastUsed != 0 {
		age = a.Now() - v.LastUsed
	}
	if v.Size != nil {
		size = *v.Size
	}
	return map[string]any{"path": v.Folder, "owner": owner, "kind": kind, "job": job, "last_used": v.LastUsed, "age_s": age, "ttl": ttl, "expired": v.Expired, "safe": v.Safe, "size": size, "action": v.Action, "dest": nullableText(v.Dest), "reason": v.Reason}
}
