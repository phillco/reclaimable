package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

func (a *App) fileHashes(root string) (map[string]string, error) {
	dir, err := openPathDir(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return a.HashDir(dir, root)
}
func (a *App) fileHashesAt(rootDir *os.File, root string) (map[string]string, error) {
	dir, err := openAt(rootDir, ".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	if err := refuseExtendedDataFD(dir); err != nil {
		return nil, err
	}
	rootDev := device(info)
	out := map[string]string{}
	var visit func(*os.File, string, string) error
	visit = func(parent *os.File, relative, logical string) error {
		before, statErr := parent.Stat()
		if statErr != nil {
			return statErr
		}
		a.fsBefore("hash-read-dir", logical, ".")
		entries, err := parent.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			st, err := a.StatAt(parent, name, false)
			if err != nil {
				return err
			}
			if name == ".DS_Store" && !st.IsDir() {
				continue
			}
			rel := filepath.Join(relative, name)
			path := filepath.Join(logical, name)
			a.fsBefore("hash-entry", logical, name)
			switch {
			case st.Mode()&os.ModeSymlink != 0:
				target, err := readlinkAt(parent, name)
				if err != nil {
					return err
				}
				fresh, err := a.StatAt(parent, name, false)
				if err != nil || !sameIdentity(st, fresh) {
					return fmt.Errorf("entry changed during hashing: %s", path)
				}
				pinned, pinErr := pinSymlinkAt(parent, name)
				if pinErr != nil {
					return pinErr
				}
				pinnedInfo, statErr := pinned.Stat()
				if statErr != nil || !unchangedFile(st, pinnedInfo) {
					pinned.Close()
					return fmt.Errorf("symlink changed during hashing: %s", path)
				}
				attrErr := refuseSymlinkExtendedDataAt(parent, name, pinned)
				finalInfo, finalErr := a.StatAt(parent, name, false)
				if finalErr != nil || !unchangedFile(st, finalInfo) {
					pinned.Close()
					return fmt.Errorf("symlink changed during hashing: %s", path)
				}
				pinned.Close()
				if attrErr != nil {
					return attrErr
				}
				out[rel] = "link:" + target
			case st.IsDir():
				if device(st) != rootDev {
					return fmt.Errorf("hash walk crosses filesystem at %s", path)
				}
				a.fsBefore("hash-descend", logical, name)
				child, err := openAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
				if err != nil {
					return err
				}
				opened, err := child.Stat()
				if err != nil || !sameIdentity(st, opened) {
					child.Close()
					return fmt.Errorf("directory changed during hashing: %s", path)
				}
				if attrErr := refuseExtendedDataFD(child); attrErr != nil {
					child.Close()
					return attrErr
				}
				err = visit(child, rel, path)
				child.Close()
				if err != nil {
					return err
				}
				current, statErr := a.StatAt(parent, name, false)
				if statErr != nil || !sameIdentity(st, current) {
					return fmt.Errorf("directory changed during hashing: %s", path)
				}
			case st.Mode().IsRegular():
				child, err := openAt(parent, name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
				if err != nil {
					return err
				}
				opened, err := child.Stat()
				if err != nil || !sameIdentity(st, opened) || !opened.Mode().IsRegular() {
					child.Close()
					return fmt.Errorf("file changed during hashing: %s", path)
				}
				if attrErr := refuseExtendedDataFD(child); attrErr != nil {
					child.Close()
					return attrErr
				}
				a.fsBefore("hash-read", logical, name)
				h := sha256.New()
				_, err = io.Copy(h, child)
				after, statErr := child.Stat()
				current, pathErr := a.StatAt(parent, name, false)
				closeErr := child.Close()
				if pathErr != nil || !unchangedFile(opened, current) {
					return fmt.Errorf("file changed during hashing: %s", path)
				}
				if err != nil {
					return err
				}
				if statErr != nil {
					return statErr
				}
				if closeErr != nil {
					return closeErr
				}
				if !unchangedFile(after, opened) {
					return fmt.Errorf("file changed during hashing: %s", path)
				}
				out[rel] = fmt.Sprintf("%x", h.Sum(nil))
			default:
				return fmt.Errorf("cannot hash special file %s", path)
			}
		}
		after, statErr := parent.Stat()
		if statErr != nil {
			return statErr
		}
		if !unchangedFile(before, after) {
			return fmt.Errorf("directory changed during hashing: %s", logical)
		}
		return nil
	}
	err = visit(dir, "", root)
	return out, err
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
func (a *App) remoteRun(remote []string, host, script string) Result {
	if len(remote) == 0 {
		remote = defaultRemoteCommand
	}
	cmd := make([]string, len(remote))
	for i, arg := range remote {
		cmd[i] = strings.ReplaceAll(strings.ReplaceAll(arg, "{host}", host), "{script}", script)
	}
	return a.Run(cmd, 300, "", nil)
}
func (a *App) remoteHashes(host, path string, remote []string) (map[string]string, error) {
	res := a.remoteRun(remote, host, remoteArchiveScript("hash", path))
	if res.Err != nil || res.Timeout || res.Code != 0 {
		return nil, fmt.Errorf("remote hash failed")
	}
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("invalid remote manifest")
	}
	out := map[string]string{}
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return nil, err
		}
		rel, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid manifest path")
		}
		if _, ok := out[rel]; ok {
			return nil, fmt.Errorf("duplicate manifest path")
		}
		if rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.ContainsRune(rel, 0) {
			return nil, fmt.Errorf("invalid manifest path")
		}
		var digest string
		if err = dec.Decode(&digest); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(digest, "link:") {
			if len(digest) != 64 {
				return nil, fmt.Errorf("invalid remote checksum")
			}
			for _, c := range digest {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return nil, fmt.Errorf("invalid remote checksum")
				}
			}
		}
		out[rel] = digest
	}
	if _, err = dec.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing remote manifest data")
	}
	return out, nil
}

func (a *App) moveDestination(destRoot, folder string) (host, dest string) {
	host, root, found := strings.Cut(destRoot, ":")
	if !found || strings.Contains(host, "/") {
		host = ""
		root = destRoot
	}
	rel := a.Hostname() + folder
	if host == "" {
		return "", filepath.Join(a.expand(root), rel)
	}
	return host, strings.TrimRight(root, "/") + "/" + rel
}
func withoutMarker(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k != markerName {
			out[k] = v
		}
	}
	return out
}
func pyStrings(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + strings.ReplaceAll(strings.ReplaceAll(v, "\\", "\\\\"), "'", "\\'") + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
func (a *App) moveAndVerify(folder, destRoot string, remote []string, src map[string]string) (bool, string) {
	host, dest := a.moveDestination(destRoot, folder)
	var err error
	if src == nil {
		src, err = a.FileHashes(folder)
		if err != nil {
			return false, "source hash failed: " + err.Error()
		}
	}
	src = withoutMarker(src)
	var got map[string]string
	if host != "" {
		ok, detail := a.remoteCopyVerified(folder, dest, host, remote, src)
		if !ok {
			return false, detail
		}
		got, err = a.remoteHashes(host, dest, remote)
		if err != nil {
			return false, "remote hash failed"
		}
	} else {
		if _, err = os.Lstat(dest); err == nil {
			return false, "destination exists: " + dest
		} else if !os.IsNotExist(err) {
			return false, "destination unreadable: " + err.Error()
		}
		target, copyErr := a.copyTreePinned(folder, dest)
		if copyErr != nil {
			return false, "copy failed: " + copyErr.Error()
		}
		defer target.Close()
		a.fsBefore("verify-copy-root", filepath.Dir(dest), filepath.Base(dest))
		got, err = a.HashDir(target, dest)
		if err == nil {
			current, openErr := openPathDir(dest)
			if openErr != nil {
				return false, "destination changed during verification: " + openErr.Error()
			}
			now, statErr := current.Stat()
			current.Close()
			want, wantErr := target.Stat()
			if statErr != nil || wantErr != nil || !sameIdentity(now, want) {
				return false, "destination changed during verification"
			}
		}
		if err != nil {
			return false, "destination hash failed: " + err.Error()
		}
	}
	got = withoutMarker(got)
	prefix := ""
	if host != "" {
		prefix = host + ":"
	}
	if !reflect.DeepEqual(got, src) {
		missing, changed := []string{}, []string{}
		for k, v := range src {
			if seen, ok := got[k]; !ok {
				missing = append(missing, k)
			} else if seen != v {
				changed = append(changed, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(changed)
		if len(missing) > 3 {
			missing = missing[:3]
		}
		if len(changed) > 3 {
			changed = changed[:3]
		}
		return false, fmt.Sprintf("hash mismatch at %s%s (missing %s, changed %s)", prefix, dest, pyStrings(missing), pyStrings(changed))
	}
	current, hashErr := a.FileHashes(folder)
	if hashErr != nil {
		return false, "source hash failed: " + hashErr.Error()
	}
	if !reflect.DeepEqual(withoutMarker(current), src) {
		return false, "source changed while it was being copied"
	}
	return true, prefix + dest
}
func (a *App) rmtreeSameDev(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := openPathDir(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	st, err := a.StatAt(parent, name, false)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("refusing to remove %s: not a real directory", path)
	}
	return a.clearDirectoryAt(parent, name, path, st)
}
func (a *App) clearDirectoryAt(parent *os.File, name, logical string, want os.FileInfo) ([]string, error) {
	dev := device(want)
	left := []string{}
	var clear func(*os.File, string, string, os.FileInfo) bool
	clear = func(parent *os.File, name, path string, want os.FileInfo) bool {
		a.fsBefore("remove-open", filepath.Dir(path), name)
		dir, err := openAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			left = append(left, path)
			return false
		}
		defer dir.Close()
		opened, err := dir.Stat()
		if err != nil || !sameIdentity(want, opened) || device(opened) != dev {
			left = append(left, path)
			return false
		}
		a.fsBefore("remove-read-dir", path, ".")
		entries, err := dir.ReadDir(-1)
		if err != nil {
			left = append(left, path)
			return false
		}
		ok := true
		for _, entry := range entries {
			leaf := entry.Name()
			childPath := filepath.Join(path, leaf)
			st, err := a.StatAt(dir, leaf, false)
			if err != nil {
				left = append(left, childPath)
				ok = false
				continue
			}
			if device(st) != dev {
				left = append(left, childPath)
				ok = false
				continue
			}
			if st.IsDir() {
				if !clear(dir, leaf, childPath, st) {
					ok = false
				}
				continue
			}
			a.fsBefore("remove-unlink", path, leaf)
			if err := unlinkAt(dir, leaf, false); err != nil {
				left = append(left, childPath)
				ok = false
			}
		}
		if !ok {
			return false
		}
		fresh, err := a.StatAt(parent, name, false)
		if err != nil || !sameIdentity(want, fresh) {
			left = append(left, path)
			return false
		}
		a.fsBefore("remove-rmdir", filepath.Dir(path), name)
		if err := unlinkAt(parent, name, true); err != nil {
			left = append(left, path)
			return false
		}
		return true
	}
	clear(parent, name, logical, want)
	return left, nil
}

func (a *App) removeFolder(v *Verdict, armed bool, cfg *Config, reg map[string]any, floorPressure ...bool) (bool, string) {
	pressure := len(floorPressure) > 0 && floorPressure[0]
	if !armed {
		return false, "dry-run"
	}
	if v.Marker == nil {
		return false, "marker unavailable"
	}
	if isMount(v.Folder) {
		return false, "folder is a mount point"
	}
	ident, err := a.Lstat(v.Folder)
	if err != nil {
		return false, "folder unreadable: " + err.Error()
	}
	if v.DirectoryID != nil && (*v.DirectoryID != (FileIdentity{device(ident), inode(ident)})) {
		return false, "folder replaced since evaluation"
	}
	sourceParent, err := openPathDir(filepath.Dir(v.Folder))
	if err != nil {
		return false, "folder parent unreadable: " + err.Error()
	}
	defer sourceParent.Close()
	sourceName := filepath.Base(v.Folder)
	anchored, err := a.StatAt(sourceParent, sourceName, false)
	if err != nil || !sameIdentity(ident, anchored) {
		return false, "folder replaced before descriptor anchoring"
	}
	sourceRoot, err := openAt(sourceParent, sourceName, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, "folder unreadable: " + err.Error()
	}
	defer sourceRoot.Close()
	opened, err := sourceRoot.Stat()
	if err != nil || !sameIdentity(ident, opened) {
		return false, "folder replaced before descriptor anchoring"
	}
	recheck := func(src map[string]string) string {
		fresh, err := a.readMarkerAt(sourceRoot, v.Folder, markerName)
		if err != nil {
			return "marker changed: " + err.Error()
		}
		if fresh.Mtime != v.Marker.Mtime || len(fresh.Holds) > 0 {
			return "marker touched or held since evaluation"
		}
		if a.denyReason(v.Folder, cfg) != "" {
			return "refused by deny-list"
		}
		st, err := a.Lstat(v.Folder)
		if err != nil {
			return "folder unreadable: " + err.Error()
		}
		if device(st) != device(ident) || inode(st) != inode(ident) {
			return "folder replaced since evaluation"
		}
		if hold := a.holderHold(fresh, cfg); hold != "" {
			return "held: " + hold
		}
		if busy := a.OpenFiles(v.Folder); busy != "" {
			return busy
		}
		var closedAt *float64
		if fresh.Job != "" {
			closed, at, detail := a.jobClosedFresh(fresh.Job, cfg, reg)
			closedAt = at
			if closed == nil || !*closed {
				if closed == nil {
					detail = "state unknown: " + detail
				}
				return "job " + fresh.Job + " " + detail
			}
		}
		if reason := a.sessionProblem(fresh, cfg, markerEntry(reg, v.Folder, a.Now()), closedAt); reason != "" {
			return reason
		}
		if !pressure {
			start := fresh.Mtime
			if fresh.Job != "" && closedAt != nil {
				start = max(start, *closedAt)
			}
			if fresh.Session != "" {
				start = max(start, number(markerEntry(reg, v.Folder, a.Now())["session_exit_seen"]))
			}
			ttl, err := parseTTL(a.markerTTL(fresh))
			if err != nil {
				return "bad marker: " + err.Error()
			}
			if a.Now()-start < ttl {
				return fmt.Sprintf("no longer expired (clock restarted %s ago, ttl %s)", humanAge(a.Now()-start), humanAge(ttl))
			}
		}
		w := a.walkAt(sourceRoot, v.Folder, cfg, true, 300)
		reason, repo := a.treeProblem(v.Folder, fresh, cfg, w)
		if reason != "" {
			return reason
		}
		if repo != v.Repo {
			return "repository type changed since evaluation"
		}
		if src != nil {
			current, err := a.HashDir(sourceRoot, v.Folder)
			if err != nil {
				return "source hash failed: " + err.Error()
			}
			if !reflect.DeepEqual(withoutMarker(current), src) {
				return "source changed while it was being copied"
			}
		}
		return ""
	}
	unlock, err := a.HoldLock()
	if err != nil {
		return false, "hold lock failed: " + err.Error()
	}
	problem := recheck(nil)
	unlock()
	if problem != "" {
		return false, problem
	}
	destDetail := ""
	var src map[string]string
	if v.Action == "move" {
		src, err = a.FileHashes(v.Folder)
		if err != nil {
			return false, "kept source: source hash failed: " + err.Error()
		}
		src = withoutMarker(src)
		ok, detail := a.MoveAndVerify(v.Folder, v.Dest, cfg.RemoteCommand, src)
		if !ok {
			return false, "kept source: " + detail
		}
		destDetail = " -> " + detail
	}
	unlock, err = a.HoldLock()
	if err != nil {
		return false, "hold lock failed: " + err.Error()
	}
	var common, trash string
	ok, detail := func() (bool, string) {
		defer unlock()
		if problem := recheck(src); problem != "" {
			return false, "kept source" + destDetail + ": " + problem
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return false, "quarantine name failed: " + err.Error()
		}
		trash = filepath.Join(filepath.Dir(v.Folder), fmt.Sprintf(".%s.reclaimable-trash-%x", sourceName, nonce))
		if v.Repo == "git-linked" {
			res := a.Run([]string{"git", "-C", v.Folder, "rev-parse", "--git-common-dir"}, 30, "", nil)
			if res.Err == nil && !res.Timeout && res.Code == 0 {
				common = strings.TrimSpace(res.Stdout)
				if !filepath.IsAbs(common) {
					common = filepath.Join(v.Folder, common)
				}
				if real, err := filepath.EvalSymlinks(common); err == nil {
					common = real
				}
			}
		}
		if v.Repo == "jj-secondary" {
			res := a.Run([]string{"jj", "-R", v.Folder, "--ignore-working-copy", "workspace", "forget"}, 60, "", nil)
			if res.Err != nil || res.Timeout || res.Code != 0 {
				detail := strings.TrimSpace(res.Stderr)
				if len(detail) > 100 {
					detail = detail[:100]
				}
				return false, "jj workspace forget failed: " + detail
			}
		}
		a.fsBefore("remove-rename", filepath.Dir(v.Folder), sourceName)
		a.fsBefore("remove-quarantine", filepath.Dir(v.Folder), filepath.Base(trash))
		currentParent, openErr := openPathDir(filepath.Dir(v.Folder))
		if openErr != nil {
			return false, "folder parent changed before rename"
		}
		currentParentInfo, statErr := currentParent.Stat()
		currentParent.Close()
		pinnedParentInfo, pinErr := sourceParent.Stat()
		if statErr != nil || pinErr != nil || !sameIdentity(currentParentInfo, pinnedParentInfo) {
			return false, "folder parent changed before rename"
		}
		if err := renameAt(sourceParent, sourceName, sourceParent, filepath.Base(trash)); err != nil {
			return false, "rename failed: " + err.Error()
		}
		st, err := a.StatAt(sourceParent, filepath.Base(trash), false)
		if err != nil || !st.IsDir() {
			if err := renameAt(sourceParent, filepath.Base(trash), sourceParent, sourceName); err != nil {
				return false, "folder became a symlink; restore failed: " + err.Error()
			}
			return false, "folder became a symlink; restored, nothing deleted"
		}
		if device(st) != device(ident) || inode(st) != inode(ident) {
			if err := renameAt(sourceParent, filepath.Base(trash), sourceParent, sourceName); err != nil {
				return false, "folder replaced before rename; restore failed: " + err.Error()
			}
			return false, "folder replaced before rename; restored, nothing deleted"
		}
		return true, ""
	}()
	if !ok {
		return false, detail
	}
	left, err := a.clearDirectoryAt(sourceParent, filepath.Base(trash), trash, ident)
	if err != nil {
		return false, "removal failed: " + err.Error()
	}
	if common != "" {
		a.Run([]string{"git", "--git-dir", common, "worktree", "prune"}, 60, "", nil)
	}
	delete(mapEntry(reg, "markers"), v.Folder)
	if len(left) > 0 {
		destDetail += fmt.Sprintf(" (left %s holding %d other-filesystem dirs)", trash, len(left))
	}
	return true, destDetail
}
