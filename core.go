package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

var denyPaths = []string{"~/.ssh", "~/.gnupg", "~/Library/Keychains"}
var denyNames = []string{"*.photoslibrary"}
var broad = []string{"/", "/Users", "/Volumes", "/System", "/Library", "/Applications", "/private", "/tmp", "/private/tmp", "/opt", "/usr", "~", "~/Documents", "~/Desktop", "~/Downloads", "~/Pictures", "~/Music", "~/Movies", "~/Library", "~/.local", "~/.local/share", "~/.local/state", "~/.config", "~/.ssh", "~/Applications", "~/.cache"}
var pruneNames = map[string]bool{".git": true, ".jj": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".Trash": true, "DerivedData": true, ".build": true, "target": true}
var prunePaths = []string{"~/Library", "~/.Trash", "~/Pictures", "~/Music", "~/Movies"}
var ttlPattern = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*$`)
var sizePattern = regexp.MustCompile(`(?i)^\s*(\d+(?:\.\d+)?)\s*(GiB|GB|G|TiB|TB|T)?\s*$`)

func pyRepr(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "'", "\\'") + "'"
}
func parseTTL(s string) (float64, error) {
	m := ttlPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("bad ttl %s (use e.g. 30m, 24h, 3d, 1w)", pyRepr(s))
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v * map[string]float64{"s": 1, "m": 60, "h": 3600, "d": day, "w": 604800}[m[2]], nil
}
func parseSize(s string) (int64, error) {
	m := sizePattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("bad size %s (e.g. 30, 30GB, 50GiB)", pyRepr(s))
	}
	n, _ := strconv.ParseFloat(m[1], 64)
	unit := strings.ToLower(m[2])
	if unit == "" {
		unit = "gb"
	}
	mult := map[string]float64{"gib": 1 << 30, "gb": 1e9, "g": 1e9, "tib": 1 << 40, "tb": 1e12, "t": 1e12}[unit]
	if math.IsNaN(n) || math.IsInf(n, 0) || n*mult >= math.Exp2(63) {
		return 0, fmt.Errorf("size too large")
	}
	return int64(n * mult), nil
}
func humanBytes(n *int64) string {
	if n == nil {
		return "?"
	}
	for _, u := range []struct {
		unit string
		size int64
	}{{"TB", 1000000000000}, {"GB", gb}, {"MB", 1000000}, {"KB", 1000}} {
		if *n >= u.size {
			return fmt.Sprintf("%.1f %s", float64(*n)/float64(u.size), u.unit)
		}
	}
	return fmt.Sprintf("%d B", *n)
}
func humanAge(s float64) string {
	if s < 0 {
		s = 0
	}
	n := int64(s)
	if n < 3600 {
		return fmt.Sprintf("%dm", n/60)
	}
	if n < 86400 {
		return fmt.Sprintf("%dh", n/3600)
	}
	return fmt.Sprintf("%.1fd", float64(n)/86400)
}
func clock(ts float64) string { return strings.ToLower(time.Unix(0, int64(ts*1e9)).Format("3:04pm")) }
func listAny(v any) ([]any, bool) {
	if v == nil {
		return nil, false
	}
	r := reflect.ValueOf(v)
	if r.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, r.Len())
	for i := range out {
		out[i] = r.Index(i).Interface()
	}
	return out, true
}
func stringsKey(raw map[string]any, key string) ([]string, error) {
	v, ok := raw[key]
	if !ok {
		return nil, nil
	}
	s, ok := stringList(v)
	if !ok {
		return nil, fmt.Errorf("config key %s must be a list of strings", pyRepr(key))
	}
	return s, nil
}
func command(table map[string]any, where string) ([]string, error) {
	cmd, ok := stringList(table["command"])
	if !ok || len(cmd) == 0 {
		return nil, fmt.Errorf("%s needs command = [..] (list of strings)", where)
	}
	return cmd, nil
}
func sizeKey(raw map[string]any, name string, def int64) (int64, error) {
	if v, ok := raw[name+"_gb"]; ok {
		n, e := strconv.ParseFloat(fmt.Sprint(v), 64)
		if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n*float64(gb) >= math.Exp2(63) || n*float64(gb) < -math.Exp2(63) {
			return 0, fmt.Errorf("invalid %s_gb", name)
		}
		return int64(n * float64(gb)), nil
	}
	if v, ok := raw[name]; ok {
		return parseSize(fmt.Sprint(v))
	}
	return def, nil
}
func (a *App) applyHostSection(raw map[string]any) (map[string]any, error) {
	hosts := dict(raw["hosts"])
	if _, ok := raw["hosts"]; ok && hosts == nil {
		return nil, errors.New("[hosts] must hold [hosts.<hostname>] tables")
	}
	var mine map[string]any
	for k, v := range hosts {
		if strings.ToLower(k) == a.Hostname() {
			mine = dict(v)
			if mine == nil {
				return nil, fmt.Errorf("[hosts.%s] must be a table", a.Hostname())
			}
		}
	}
	if mine == nil {
		return raw, nil
	}
	out := map[string]any{}
	for k, v := range raw {
		out[k] = v
	}
	for _, family := range [][]string{{"floor", "floor_gb"}, {"target", "target_gb"}} {
		_, one := mine[family[0]]
		_, two := mine[family[1]]
		if one || two {
			for _, k := range family {
				delete(out, k)
			}
		}
	}
	for _, k := range []string{"floor", "floor_gb", "target", "target_gb", "move_root", "roots", "volume_floors", "maintenance", "maintenance_armed", "maintenance_only", "busy_holders"} {
		if v, ok := mine[k]; ok {
			out[k] = v
		}
	}
	for _, k := range []string{"deny", "deny_names", "deny_exact"} {
		if _, ok := mine[k]; ok {
			base, e := stringsKey(raw, k)
			if e != nil {
				return nil, e
			}
			add, e := stringsKey(mine, k)
			if e != nil {
				return nil, e
			}
			out[k] = append(append([]string{}, base...), add...)
		}
	}
	return out, nil
}
func (a *App) loadConfig(path string) (*Config, error) {
	raw := map[string]any{}
	_, e := toml.DecodeFile(path, &raw)
	if e != nil && !os.IsNotExist(e) {
		return nil, fmt.Errorf("cannot read %s: %v", path, e)
	}
	raw, e = a.applyHostSection(raw)
	if e != nil {
		return nil, e
	}
	roots, e := stringsKey(raw, "roots")
	if e != nil {
		return nil, e
	}
	for i := range roots {
		roots[i] = a.expand(roots[i])
	}
	if len(roots) == 0 {
		roots = a.defaultRoots()
	}
	floor, e := sizeKey(raw, "floor", 30*gb)
	if e != nil {
		return nil, e
	}
	target, e := sizeKey(raw, "target", floor+targetMargin)
	if e != nil {
		return nil, e
	}
	if target < floor {
		target = floor
	}
	ttls := dict(raw["default_ttls"])
	if _, ok := raw["default_ttls"]; ok && ttls == nil {
		return nil, errors.New("default_ttls keys must be among ('cache', 'scratch', 'worktree', 'mirror', 'staged')")
	}
	for k, v := range ttls {
		if !contains(kinds, k) {
			return nil, errors.New("default_ttls keys must be among ('cache', 'scratch', 'worktree', 'mirror', 'staged')")
		}
		s := fmt.Sprint(v)
		if _, e = parseTTL(s); e != nil {
			return nil, e
		}
		a.DefaultTTL[k] = s
	}
	sequences := [][]string{}
	if v, ok := raw["deny_sequences"]; ok {
		ss, ok := listAny(v)
		if !ok {
			return nil, errors.New("deny_sequences must be lists of names")
		}
		for _, s := range ss {
			seq, ok := stringList(s)
			if !ok || len(seq) == 0 {
				return nil, errors.New("deny_sequences must be lists of names")
			}
			sequences = append(sequences, seq)
		}
	}
	holders := []map[string]any{}
	if v, ok := raw["holder"]; ok {
		hs, ok := listAny(v)
		if !ok {
			return nil, errors.New("[[holder]] entries must be tables")
		}
		for i, h := range hs {
			m := dict(h)
			if m == nil {
				return nil, errors.New("[[holder]] entries must be tables")
			}
			if _, ok := m["command"]; ok {
				if _, e = command(m, fmt.Sprintf("[[holder]] #%d", i+1)); e != nil {
					return nil, e
				}
			} else if _, ok := m["lease_dir"]; !ok {
				return nil, fmt.Errorf("[[holder]] #%d needs command or lease_dir", i+1)
			}
			holders = append(holders, m)
		}
	}
	jobDone := dict(raw["job_done"])
	if v, ok := raw["job_done"]; ok {
		if dict(v) == nil {
			return nil, errors.New("[job_done] must be a table")
		}
		if _, e = command(jobDone, "[job_done]"); e != nil {
			return nil, e
		}
	}
	var grace *float64
	if v, ok := raw["session_grace"]; ok {
		n, e := parseTTL(fmt.Sprint(v))
		if e != nil {
			return nil, e
		}
		grace = &n
	}
	remote := append([]string{}, defaultRemoteCommand...)
	if v, ok := raw["remote_command"]; ok {
		remote, e = command(map[string]any{"command": v}, "remote_command")
		if e != nil {
			return nil, e
		}
	}
	dps, e := stringsKey(raw, "deny")
	if e != nil {
		return nil, e
	}
	dns, e := stringsKey(raw, "deny_names")
	if e != nil {
		return nil, e
	}
	dex, e := stringsKey(raw, "deny_exact")
	if e != nil {
		return nil, e
	}
	volumes := map[string]int64{}
	if v, ok := raw["volume_floors"]; ok {
		m := dict(v)
		if m == nil {
			return nil, errors.New("volume_floors must be a table")
		}
		for k, v := range m {
			n, e := parseSize(fmt.Sprint(v))
			if e != nil {
				return nil, e
			}
			volumes[a.pathKey(k)] = n
		}
	}
	format := "{path}"
	if v, ok := raw["exclude_list_format"]; ok {
		format = fmt.Sprint(v)
	}
	export := ""
	if truth(raw["exclude_list_path"]) {
		export = a.expand(textValue(raw["exclude_list_path"]))
	}
	maintenanceOnly := false
	if v, exists := raw["maintenance_only"]; exists {
		var ok bool
		maintenanceOnly, ok = v.(bool)
		if !ok {
			return nil, errors.New("maintenance_only must be true or false")
		}
	}
	maintenance, maintenanceArmed, e := parseMaintenance(raw, holders, path)
	if e != nil {
		return nil, e
	}
	return &Config{Maintenance: maintenance, MaintenanceArmed: maintenanceArmed, MaintenanceOnly: maintenanceOnly, Roots: roots, Floor: floor, Target: target, MoveRoot: textValue(raw["move_root"]), DenyPaths: append(append([]string{}, denyPaths...), dps...), DenyNames: append(append([]string{}, denyNames...), dns...), DenyExact: append(append([]string{}, broad...), dex...), DenySequences: sequences, VolumeFloors: volumes, Holders: holders, JobDone: jobDone, ExportList: export, ExportFormat: format, RemoteCommand: remote, SessionGrace: grace}, nil
}
func contains(items []string, s string) bool {
	for _, x := range items {
		if x == s {
			return true
		}
	}
	return false
}
func (a *App) defaultRoots() []string {
	return a.defaultRootsWith("/Volumes", 2, defaultRootCommand)
}

func writable(p string) bool { return syscall.Access(p, 2|4|1) == nil }

func (a *App) parseMarker(content []byte, folder string, st os.FileInfo) (*Marker, error) {
	var e error
	var v any
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	if !json.Valid(content) {
		if e = json.Unmarshal(content, &v); e != nil {
			return nil, e
		}
	}
	if e = dec.Decode(&v); e != nil {
		return nil, e
	}
	if v == nil {
		return nil, errors.New("marker is not a JSON object")
	}
	data := dict(v)
	if data == nil {
		return nil, errors.New("marker is not a JSON object")
	}
	owner, ok := data["owner"].(string)
	if !ok || strings.TrimSpace(owner) == "" {
		return nil, errors.New("marker needs an owner")
	}
	regenerate, ok := data["regenerate"].(string)
	if !ok || strings.TrimSpace(regenerate) == "" {
		return nil, errors.New("marker needs a regenerate description")
	}
	if value, exists := data["ignored_ok"]; exists {
		if _, ok := value.(bool); !ok {
			return nil, errors.New("ignored_ok must be true or false")
		}
	}
	kind := ""
	if data["kind"] != nil {
		var ok bool
		kind, ok = data["kind"].(string)
		if !ok || !contains(kinds, kind) {
			return nil, fmt.Errorf("unknown kind %s", pyRepr(fmt.Sprint(data["kind"])))
		}
	}
	ttl := ""
	if data["ttl"] != nil {
		ttl = fmt.Sprint(data["ttl"])
		if _, e = parseTTL(ttl); e != nil {
			return nil, e
		}
	}
	holds := []map[string]any{}
	if truth(data["holds"]) {
		hs, ok := listAny(data["holds"])
		if !ok {
			return nil, errors.New("holds must be a list of objects")
		}
		for _, h := range hs {
			m := dict(h)
			if m == nil {
				return nil, errors.New("holds must be a list of objects")
			}
			holds = append(holds, m)
		}
	}
	extra := map[string]any{}
	for k, v := range data {
		if !contains([]string{"owner", "ttl", "regenerate", "kind", "job", "session", "move_to", "holds"}, k) {
			extra[k] = v
		}
	}
	return &Marker{Folder: folder, Owner: owner, TTL: ttl, Regenerate: regenerate, Kind: kind, Job: textValue(data["job"]), JobPresent: data["job"] != nil, Session: textValue(data["session"]), MoveTo: textValue(data["move_to"]), Holds: holds, Mtime: float64(st.ModTime().UnixNano()) / 1e9, Extra: extra}, nil
}
func (m *Marker) toJSON() map[string]any {
	data := map[string]any{}
	for k, v := range m.Extra {
		data[k] = v
	}
	data["owner"] = m.Owner
	data["regenerate"] = m.Regenerate
	holds := m.Holds
	if holds == nil {
		holds = []map[string]any{}
	}
	data["holds"] = holds
	for k, v := range map[string]string{"ttl": m.TTL, "kind": m.Kind, "job": m.Job, "session": m.Session, "move_to": m.MoveTo} {
		if v != "" {
			data[k] = v
		} else {
			delete(data, k)
		}
	}
	return data
}
func (a *App) writeMarker(m *Marker) error {
	if e := writeJSON(m.path(), m.toJSON()); e != nil {
		return e
	}
	st, e := os.Stat(m.path())
	if e == nil {
		m.Mtime = float64(st.ModTime().UnixNano()) / 1e9
	}
	return e
}

// globMatch follows fnmatchcase: wildcards include separators, and dotfiles are
// ordinary names. filepath.Match has different separator semantics.
func globMatch(name, pattern string) bool {
	var out strings.Builder
	out.WriteString("(?s)^")
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '*':
			out.WriteString(".*")
		case '?':
			out.WriteByte('.')
		case '[':
			j := i + 1
			if j < len(runes) && runes[j] == '!' {
				j++
			}
			if j < len(runes) && runes[j] == ']' {
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				j++
			}
			if j == len(runes) {
				out.WriteString(`\[`)
				continue
			}
			content := runes[i+1 : j]
			chunks := [][]rune{}
			begin := 0
			k := 1
			if len(content) > 0 && content[0] == '!' {
				k = 2
			}
			for {
				for k < len(content) && content[k] != '-' {
					k++
				}
				if k >= len(content) {
					break
				}
				chunks = append(chunks, append([]rune{}, content[begin:k]...))
				begin = k + 1
				k += 3
			}
			tail := append([]rune{}, content[begin:]...)
			if len(tail) > 0 {
				chunks = append(chunks, tail)
			} else if len(chunks) > 0 {
				chunks[len(chunks)-1] = append(chunks[len(chunks)-1], '-')
			}
			for k := len(chunks) - 1; k > 0; k-- {
				left, right := chunks[k-1], chunks[k]
				if left[len(left)-1] > right[0] {
					chunks[k-1] = append(left[:len(left)-1], right[1:]...)
					chunks = append(chunks[:k], chunks[k+1:]...)
				}
			}
			empty := len(chunks) == 0 || len(chunks) == 1 && len(chunks[0]) == 0
			negEmpty := len(chunks) == 1 && string(chunks[0]) == "!"
			if empty {
				out.WriteString(`\b\B`)
				i = j
				continue
			}
			if negEmpty {
				out.WriteByte('.')
				i = j
				continue
			}
			out.WriteByte('[')
			for n, chunk := range chunks {
				if n > 0 {
					out.WriteByte('-')
				}
				for k, r := range chunk {
					if n == 0 && k == 0 && r == '!' {
						out.WriteByte('^')
						continue
					}
					if r == '\\' || r == ']' || r == '[' || r == '^' || r == '-' {
						out.WriteByte('\\')
					}
					out.WriteRune(r)
				}
			}
			out.WriteByte(']')
			i = j
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	out.WriteByte('$')
	re, e := regexp.Compile(out.String())
	return e == nil && re.MatchString(name)
}

func pathParts(p string) []string {
	p = filepath.Clean(p)
	if p == "/" {
		return []string{"/"}
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if strings.HasPrefix(p, "/") {
		parts = append([]string{"/"}, parts...)
	}
	return parts
}
func ancestors(p string) []string {
	var out []string
	for {
		out = append(out, p)
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	return out
}

var dataVolume = "/System/Volumes/Data"

type FileIdentity struct{ Dev, Ino uint64 }

func stripData(path string) string {
	parts, prefix := pathParts(path), pathParts(dataVolume)
	if len(parts) >= len(prefix) {
		same := true
		for i, p := range prefix {
			if fold(parts[i]) != fold(p) {
				same = false
				break
			}
		}
		if same {
			return filepath.Join(append([]string{"/"}, parts[len(prefix):]...)...)
		}
	}
	return filepath.Clean(path)
}
func pathKey(path string) string {
	home, _ := os.UserHomeDir()
	if path == "~" {
		path = home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, path[2:])
	}
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	return fold(stripData(path))
}
func (a *App) pathKey(path string) string { return fold(a.expand(path)) }
func (a *App) pathMatch(path, pattern string) bool {
	return globMatch(a.pathKey(path), a.pathKey(pattern))
}
func (a *App) within(path, root string) bool { return keyWithin(a.pathKey(path), a.pathKey(root)) }
func pmatch(name, pattern string) bool       { return globMatch(fold(name), fold(pattern)) }
func identity(path string) (FileIdentity, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return FileIdentity{}, false
	}
	return FileIdentity{device(info), inode(info)}, true
}
func (a *App) denyTargets(cfg *Config) ([]string, error) {
	out := []string{}
	for _, raw := range cfg.DenyPaths {
		targets, err := a.expandDirs(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, targets...)
	}
	return out, nil
}
func (a *App) protectedIdentitiesChecked(cfg *Config) (map[FileIdentity]bool, error) {
	targets, err := a.denyTargets(cfg)
	if err != nil {
		return nil, err
	}
	out := map[FileIdentity]bool{}
	for _, p := range targets {
		if id, ok := a.Identity(p); ok {
			out[id] = true
		}
	}
	return out, nil
}
func (a *App) protectedIdentities(cfg *Config) map[FileIdentity]bool {
	out, _ := a.protectedIdentitiesChecked(cfg)
	return out
}
func denyNameHit(parts []string, cfg *Config) string {
	for _, part := range parts {
		for _, pat := range cfg.DenyNames {
			if pmatch(part, pat) {
				return part
			}
		}
	}
	folded := make([]string, len(parts))
	for i, p := range parts {
		folded[i] = fold(p)
	}
	for _, seq := range cfg.DenySequences {
		want := make([]string, len(seq))
		for i, p := range seq {
			want[i] = fold(p)
		}
		for i := 0; i+len(want) <= len(folded); i++ {
			if reflect.DeepEqual(folded[i:i+len(want)], want) {
				return strings.Join(seq, "/")
			}
		}
	}
	return ""
}
func (a *App) denyReason(path string, cfg *Config) string {
	path = a.expand(path)
	for _, p := range ancestors(path) {
		st, err := a.Lstat(p)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return fmt.Sprintf("symlink in path (%s); mark the real directory", p)
		}
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		real = path
	}
	real = a.expand(real)
	targets, err := a.denyTargets(cfg)
	if err != nil {
		return fmt.Sprintf("deny-list unreadable (%s)", err)
	}
	protected := map[FileIdentity]bool{}
	for _, p := range targets {
		if id, ok := a.Identity(p); ok {
			protected[id] = true
		}
	}
	candidates := []string{path}
	if real != path {
		candidates = append(candidates, real)
	}
	for _, candidate := range candidates {
		chain := ancestors(candidate)
		type identified struct {
			id FileIdentity
			ok bool
		}
		ids := make([]identified, len(chain))
		for i, p := range chain {
			ids[i].id, ids[i].ok = a.Identity(p)
		}
		cand := ids[0]
		for _, raw := range cfg.DenyExact {
			target := a.expand(raw)
			same := a.pathKey(candidate) == a.pathKey(target)
			if cand.ok {
				tid, ok := a.Identity(target)
				same = same || ok && cand.id == tid
			}
			if same {
				return "broad folder " + raw
			}
		}
		if p := a.pathKey(filepath.Dir(candidate)); p == "/users" || p == "/volumes" {
			return "home or volume root"
		}
		for _, id := range ids {
			if id.ok && protected[id.id] {
				return "deny-list (same directory as a protected path)"
			}
		}
		for _, raw := range cfg.DenyPaths {
			pattern := a.expand(raw)
			for _, anc := range chain {
				if a.pathMatch(anc, pattern) {
					return "deny-list " + raw
				}
			}
			base := pattern
			for strings.ContainsAny(base, "*?[") {
				next := filepath.Dir(base)
				if next == base {
					break
				}
				base = next
			}
			if a.within(base, candidate) {
				return "may contain deny-listed " + raw
			}
		}
		for _, target := range targets {
			same := a.within(target, candidate)
			if cand.ok && !same {
				for _, p := range ancestors(target) {
					id, ok := a.Identity(p)
					if ok && id == cand.id {
						same = true
						break
					}
				}
			}
			if same {
				return "contains deny-listed " + target
			}
		}
		parts := pathParts(candidate)
		for _, p := range parts {
			if fold(p) == ".git" || fold(p) == ".jj" {
				return "inside a .git/.jj dir"
			}
		}
		if hit := denyNameHit(parts, cfg); hit != "" {
			return "deny-listed name " + hit
		}
	}
	return ""
}

func (a *App) loadRegistry() (map[string]any, error) {
	v, e := loadJSON(a.Registry, map[string]any{})
	if e != nil {
		return nil, e
	}
	m := dict(v)
	if m == nil {
		return nil, errors.New("registry is not a JSON object")
	}
	if v, ok := m["markers"]; ok && dict(v) == nil {
		return nil, errors.New("registry markers must be an object")
	}
	mapEntry(m, "markers")
	return m, nil
}
func (a *App) saveRegistry(reg map[string]any) error { return writeJSON(a.Registry, reg) }
func (a *App) register(folder string) error {
	unlock, e := a.stateLock()
	if e != nil {
		return e
	}
	defer unlock()
	reg, e := a.loadRegistry()
	if e != nil {
		return e
	}
	markerEntry(reg, folder, a.Now())
	if e = a.saveRegistry(reg); e != nil {
		return e
	}
	cfg, e := a.LoadConfig()
	if e != nil {
		return e
	}
	return a.writeExportList(reg, cfg)
}
func (a *App) scan(roots []string, cfg *Config, limit float64) (map[string]bool, bool) {
	found := map[string]bool{}
	complete := true
	deadline := time.Now().Add(time.Duration(limit * float64(time.Second)))
	prune := map[string]bool{}
	names := map[string]bool{}
	for name := range pruneNames {
		names[fold(name)] = true
	}
	for _, p := range prunePaths {
		prune[a.pathKey(p)] = true
	}
	var visit func(*os.File, string, int, uint64)
	visit = func(dir *os.File, folder string, depth int, dev uint64) {
		if time.Now().After(deadline) {
			complete = false
			return
		}
		a.fsBefore("scan-read-dir", folder, ".")
		entries, err := dir.ReadDir(-1)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if fold(entry.Name()) == fold(markerName) {
				st, err := a.StatAt(dir, entry.Name(), false)
				if err == nil && st.Mode().IsRegular() {
					found[folder] = true
					return
				}
			}
		}
		if depth >= 8 {
			complete = false
			return
		}
		for _, entry := range entries {
			if time.Now().After(deadline) {
				complete = false
				return
			}
			name := entry.Name()
			folded := fold(name)
			if names[folded] || strings.HasSuffix(folded, ".app") || strings.HasSuffix(folded, ".photoslibrary") {
				continue
			}
			path := filepath.Join(folder, name)
			if prune[a.pathKey(path)] {
				continue
			}
			denied := false
			for _, pattern := range cfg.DenyPaths {
				if a.pathMatch(path, pattern) {
					denied = true
					break
				}
			}
			if denied {
				continue
			}
			info, err := a.StatAt(dir, name, false)
			if err != nil || !info.IsDir() || device(info) != dev {
				continue
			}
			child, err := openAt(dir, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				continue
			}
			opened, err := child.Stat()
			if err == nil && sameIdentity(info, opened) {
				visit(child, path, depth+1, dev)
				current, checkErr := a.StatAt(dir, name, false)
				if checkErr != nil || !sameIdentity(opened, current) {
					complete = false
				}
			}
			child.Close()
		}
	}
	for _, raw := range roots {
		root := a.expand(raw)
		dir, err := openPathDir(root)
		if err != nil {
			continue
		}
		info, err := dir.Stat()
		if err == nil {
			visit(dir, root, 0, device(info))
		}
		dir.Close()
	}
	return found, complete
}

func (a *App) discover(cfg *Config, reg map[string]any, force bool, roots []string) ([]string, error) {
	registered := sortedKeys(mapEntry(reg, "markers"))
	if force || len(roots) > 0 || a.Now()-number(reg["last_scan"]) > day {
		r := roots
		if len(r) == 0 {
			r = cfg.Roots
		}
		found, complete := a.scan(r, cfg, 120)
		for f := range found {
			markerEntry(reg, f, a.Now())
		}
		if len(roots) == 0 {
			reg["last_scan"] = a.Now()
			reg["last_scan_complete"] = complete
		}
	}
	out := []string{}
	markers := mapEntry(reg, "markers")
	seen := map[string]bool{}
	order := append([]string{}, registered...)
	prior := map[string]bool{}
	for _, p := range registered {
		prior[p] = true
	}
	for _, p := range sortedKeys(markers) {
		if !prior[p] {
			order = append(order, p)
		}
	}
	for _, original := range order {
		f := original
		if !filepath.IsAbs(f) {
			if err := a.log("ignoring relative registry path " + pyRepr(f)); err != nil {
				return nil, err
			}
			continue
		}
		normalized := a.expand(f)
		if normalized != f {
			value := markers[f]
			delete(markers, f)
			if _, ok := markers[normalized]; !ok {
				markers[normalized] = value
			}
			f = normalized
		}
		if seen[a.pathKey(f)] {
			continue
		}
		if !isFile(filepath.Join(f, markerName)) {
			delete(markers, f)
			continue
		}
		if len(roots) == 0 {
			out = append(out, f)
			seen[a.pathKey(f)] = true
		} else {
			for _, r := range roots {
				if a.within(f, r) {
					out = append(out, f)
					seen[a.pathKey(f)] = true
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
func (a *App) exportOK(p string) bool {
	p = a.expand(p)
	for _, anc := range ancestors(p) {
		st, err := a.Lstat(anc)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	parent := a.pathKey(filepath.Dir(p))
	return !a.IsMount(p) && parent != "/users" && parent != "/volumes" && a.pathKey(p) != a.pathKey(a.Home)
}
func (a *App) writeExportList(reg map[string]any, cfg *Config) error {
	if cfg.ExportList == "" {
		return nil
	}
	lines := []string{"# Generated by reclaimable from registered .reclaimable markers; do not edit."}
	folders := []string{}
	for f := range mapEntry(reg, "markers") {
		folders = append(folders, f)
	}
	sort.Strings(folders)
	for _, f := range folders {
		if isFile(filepath.Join(f, markerName)) && a.denyReason(f, cfg) == "" && a.exportOK(f) {
			lines = append(lines, strings.ReplaceAll(cfg.ExportFormat, "{path}", f))
		}
	}
	text := strings.Join(lines, "\n") + "\n"
	old, e := os.ReadFile(cfg.ExportList)
	if e == nil && string(old) == text {
		return nil
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(cfg.ExportList), 0755); e != nil {
		return e
	}
	return os.WriteFile(cfg.ExportList, []byte(text), 0644)
}
