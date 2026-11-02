package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Set by the release build with -ldflags "-X main.version=<tag>".
var version = "dev"

func main() { os.Exit(newApp().main(os.Args[1:])) }

func (a *App) fail(err error, code int) int {
	fmt.Fprintln(a.Err, "reclaimable:", err)
	return code
}

func (a *App) main(argv []string) int {
	if len(argv) == 1 && (argv[0] == "-V" || argv[0] == "--version") {
		fmt.Fprintln(a.Out, "reclaimable", version)
		return 0
	}
	args, help, err := parseArgs(argv)
	if err != nil {
		return a.fail(err, 2)
	}
	if help {
		a.help(args.Command)
		return 0
	}
	cfg, err := a.LoadConfig()
	if err != nil {
		return a.fail(err, 1)
	}
	switch args.Command {
	case "mark":
		return a.cmdMark(args, cfg)
	case "touch":
		return a.cmdTouch(args)
	case "hold", "release":
		return a.cmdHold(args, args.Command == "release")
	case "ls":
		return a.cmdLS(args, cfg)
	case "sweep":
		return a.sweep(args, cfg)
	case "maintenance":
		return a.cmdMaintenance(args, cfg)
	case "status":
		return a.cmdStatus(args, cfg)
	case "arm":
		return a.cmdArm(args)
	}
	return 1
}

type optionSpec struct {
	name  string
	value bool
}

func commandOptions(cmd string) map[string]optionSpec {
	out := map[string]optionSpec{"-h": {"help", false}, "--help": {"help", false}}
	add := func(short, long string, value bool) {
		s := optionSpec{long, value}
		out["-"+short] = s
		out["--"+long] = s
	}
	switch cmd {
	case "mark":
		for _, v := range [][2]string{{"o", "owner"}, {"t", "ttl"}, {"r", "regen"}, {"k", "kind"}, {"j", "job"}, {"s", "session"}, {"m", "move-to"}} {
			add(v[0], v[1], true)
		}
	case "hold", "release":
		add("p", "path", true)
	case "ls":
		add("j", "json", false)
		add("q", "quick", false)
		add("S", "scan", false)
	case "sweep":
		add("n", "dry-run", false)
		add("A", "armed", false)
		add("f", "floor", true)
		add("t", "target", true)
		add("S", "scan", false)
		add("v", "verbose", false)
	case "maintenance":
		add("n", "dry-run", false)
		add("o", "only", true)
		add("f", "force-due", false)
	case "status":
		add("l", "lines", true)
	case "arm":
		add("x", "off", false)
	}
	return out
}

// Parse flags on either side of positionals, as the original command does.
var negativeNumber = regexp.MustCompile(`^-\d+$|^-\d*\.\d+$`)

func parseArgs(argv []string) (Args, bool, error) {
	a := Args{Lines: 15}
	if len(argv) == 0 {
		return a, false, fmt.Errorf("the following arguments are required: COMMAND")
	}
	if argv[0] == "-h" || argv[0] == "--help" {
		return a, true, nil
	}
	valid := false
	for _, cmd := range []string{"mark", "touch", "hold", "release", "ls", "sweep", "maintenance", "status", "arm"} {
		if argv[0] == cmd {
			valid = true
		}
	}
	if !valid {
		return a, false, fmt.Errorf("argument COMMAND: invalid choice: %q", argv[0])
	}
	a.Command = argv[0]
	specs := commandOptions(a.Command)
	values := map[string]string{}
	flags := map[string]bool{}
	positionals := []string{}
	stop := false
	tokens := append([]string(nil), argv[1:]...)
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if stop || token == "-" || !strings.HasPrefix(token, "-") || negativeNumber.MatchString(token) {
			positionals = append(positionals, token)
			continue
		}
		if token == "--" {
			stop = true
			continue
		}
		key, val, hasEq := strings.Cut(token, "=")
		spec, ok := specs[key]
		if !ok && strings.HasPrefix(key, "--") {
			var matches []optionSpec
			for name, v := range specs {
				if strings.HasPrefix(name, key) {
					matches = append(matches, v)
				}
			}
			if len(matches) == 1 {
				spec, ok = matches[0], true
			}
		}
		if !ok && strings.HasPrefix(token, "-") && !strings.HasPrefix(token, "--") && len(token) > 2 {
			key = token[:2]
			spec, ok = specs[key]
			if ok {
				if spec.value {
					val = token[2:]
					hasEq = true
				} else {
					tokens = append(tokens[:i+1], append([]string{"-" + token[2:]}, tokens[i+1:]...)...)
				}
			}
		}
		if !ok {
			return a, false, fmt.Errorf("unrecognized arguments: %s", token)
		}
		if spec.name == "help" {
			return a, true, nil
		}
		if spec.value {
			if !hasEq {
				i++
				if i >= len(tokens) {
					return a, false, fmt.Errorf("argument %s: expected one argument", key)
				}
				val = tokens[i]
				if val != "-" && strings.HasPrefix(val, "-") && !negativeNumber.MatchString(val) {
					return a, false, fmt.Errorf("argument %s: expected one argument", key)
				}
			}
			values[spec.name] = val
		} else {
			if hasEq {
				return a, false, fmt.Errorf("argument %s: ignored explicit argument %q", key, val)
			}
			flags[spec.name] = true
		}
	}
	ptr := func(name string) *string {
		v, ok := values[name]
		if !ok {
			return nil
		}
		return &v
	}
	a.TTL = ptr("ttl")
	a.Regen = ptr("regen")
	a.Kind = ptr("kind")
	a.Job = ptr("job")
	a.Session = ptr("session")
	a.MoveTo = ptr("move-to")
	a.Subpath = ptr("path")
	a.Owner = values["owner"]
	a.Only = values["only"]
	if only, present := values["only"]; present && only == "" {
		return a, false, fmt.Errorf("--only requires a nonempty hook name")
	}
	a.ForceDue = flags["force-due"]
	a.JSON = flags["json"]
	a.Quick = flags["quick"]
	a.Scan = flags["scan"]
	a.DryRun = flags["dry-run"]
	a.Armed = flags["armed"]
	a.Verbose = flags["verbose"]
	a.Off = flags["off"]
	for key, p := range map[string]**int64{"floor": &a.Floor, "target": &a.Target} {
		if v, ok := values[key]; ok {
			n, e := parseSize(v)
			if e != nil {
				return a, false, e
			}
			*p = &n
		}
	}
	if v, ok := values["lines"]; ok {
		n, e := strconv.Atoi(v)
		if e != nil {
			return a, false, fmt.Errorf("argument -l/--lines: invalid int value: %q", v)
		}
		a.Lines = n
	}
	if a.DryRun && a.Armed {
		return a, false, fmt.Errorf("argument -A/--armed: not allowed with argument -n/--dry-run")
	}
	need := 0
	max := 0
	switch a.Command {
	case "mark":
		need, max = 1, 1
		if _, ok := values["owner"]; !ok {
			return a, false, fmt.Errorf("the following arguments are required: -o/--owner")
		}
		if a.Kind != nil {
			found := false
			for _, k := range kinds {
				if *a.Kind == k {
					found = true
				}
			}
			if !found {
				return a, false, fmt.Errorf("argument -k/--kind: invalid choice: %q", *a.Kind)
			}
		}
	case "touch":
		need, max = 1, -1
	case "hold", "release":
		need, max = 2, 2
	case "ls":
		max = -1
	}
	if len(positionals) < need {
		return a, false, fmt.Errorf("the following arguments are required: path")
	}
	if max >= 0 && len(positionals) > max {
		return a, false, fmt.Errorf("unrecognized arguments: %s", strings.Join(positionals[max:], " "))
	}
	if len(positionals) > 0 {
		a.Path = positionals[0]
	}
	switch a.Command {
	case "touch":
		a.Paths = positionals
	case "ls":
		a.Roots = positionals
	case "hold", "release":
		j := positionals[1]
		a.Job = &j
	}
	return a, false, nil
}

func (a *App) help(cmd string) {
	if cmd == "" {
		fmt.Fprintln(a.Out, "usage: reclaimable [-h] [-V] COMMAND ...\n\nJanitor for regenerable folders marked with `.reclaimable`.\n\ncommands:\n  mark     create/update a folder's .reclaimable marker\n  touch    mark folders used now\n  hold     declare a job is reading the folder\n  release  drop a job's hold\n  ls       list markers with age, size, TTL and eligibility\n  sweep    the janitor (dry-run unless this host is armed)\n  maintenance  run configured native cache hooks\n  status   armed state, free space, last sweep, log tail\n  arm      arm this host (scheduled sweeps act after 24h)\n\noptions:\n  -h, --help  show this help message and exit\n  -V, --version  show version and exit\n\nConfig: ~/.config/reclaimable/config.toml (see README)")
		return
	}
	usage := map[string]string{"mark": "PATH -o OWNER [-t TTL] [-r REGEN] [-k KIND] [-j JOB] [-s SESSION] [-m MOVE_TO]", "touch": "PATH...", "hold": "PATH JOB [-p SUBPATH]", "release": "PATH JOB [-p SUBPATH]", "ls": "[ROOTS...] [-j] [-q] [-S]", "sweep": "[-n | -A] [-f FLOOR] [-t TARGET] [-S] [-v]", "maintenance": "[-n] [-o NAME] [-f]", "status": "[-l LINES]", "arm": "[-x]"}
	fmt.Fprintf(a.Out, "usage: reclaimable %s [-h] %s\n\noptions:\n  -h, --help  show this help message and exit\n", cmd, usage[cmd])
	specs := commandOptions(cmd)
	keys := []string{}
	for k := range specs {
		if strings.HasPrefix(k, "--") && k != "--help" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, long := range keys {
		var short string
		for k, s := range specs {
			if len(k) == 2 && s.name == specs[long].name {
				short = k
			}
		}
		value := ""
		if specs[long].value {
			value = " " + strings.ToUpper(strings.ReplaceAll(specs[long].name, "-", "_"))
		}
		fmt.Fprintf(a.Out, "  %s, %s%s\n", short, long, value)
	}
}

func (a *App) armedState() (bool, string) {
	if !exists(a.ArmedFile) {
		return false, "unarmed"
	}
	raw, e := loadJSON(a.ArmedFile, nil)
	m := dict(raw)
	if e != nil || m == nil || m["armed_at"] == nil {
		return false, "unreadable " + a.ArmedFile
	}
	at := number(m["armed_at"])
	switch x := m["armed_at"].(type) {
	case float64:
	case string:
		if _, e := strconv.ParseFloat(x, 64); e != nil {
			return false, "unreadable " + a.ArmedFile
		}
	default:
		return false, "unreadable " + a.ArmedFile
	}
	if math.IsNaN(at) || math.IsInf(at, 0) {
		return false, "unreadable " + a.ArmedFile
	}
	if a.Now()-at < day {
		return false, fmt.Sprintf("armed %s ago; dry-run until 24h", humanAge(a.Now()-at))
	}
	return true, fmt.Sprintf("armed since %s %s", time.Unix(0, int64(at*1e9)).Format("2006-01-02"), clock(at))
}

func (a *App) plan(verdicts []*Verdict, cfg *Config, estimate ...bool) []Planned {
	chosen, _ := a.planChecked(verdicts, cfg, estimate...)
	return chosen
}

func (a *App) volumeLimits(folder string, cfg *Config) (floor, target int64, ok bool) {
	st, err := os.Stat(folder)
	if err != nil {
		return 0, 0, false
	}
	home, err := os.Stat(a.Home)
	if err != nil {
		return 0, 0, false
	}
	mount, err := filepath.Abs(folder)
	if err != nil {
		return 0, 0, false
	}
	for !a.IsMount(mount) && filepath.Dir(mount) != mount {
		mount = filepath.Dir(mount)
	}
	for _, key := range sortedKeys(cfg.VolumeFloors) {
		if a.pathKey(key) == a.pathKey(mount) {
			floor, ok = cfg.VolumeFloors[key], true
			break
		}
	}
	if !ok {
		if device(st) != device(home) {
			return 0, 0, false
		}
		floor = cfg.Floor
	}
	target = floor + targetMargin
	if device(st) == device(home) {
		target = cfg.Target
	}
	return floor, target, true
}

func (a *App) planChecked(verdicts []*Verdict, cfg *Config, estimateOption ...bool) ([]Planned, error) {
	estimate := len(estimateOption) == 0 || estimateOption[0]
	chosen := []Planned{}
	picked := map[*Verdict]bool{}
	for _, v := range verdicts {
		if v.Safe && v.Expired {
			chosen = append(chosen, Planned{v, "ttl expired"})
			picked[v] = true
		}
	}
	if _, e := os.Stat(a.Home); e != nil {
		return nil, e
	}
	byDev := map[uint64][]*Verdict{}
	devs := []uint64{}
	for _, v := range verdicts {
		if s, e := os.Stat(v.Folder); e == nil {
			d := device(s)
			if _, ok := byDev[d]; !ok {
				devs = append(devs, d)
			}
			byDev[d] = append(byDev[d], v)
		}
	}
	for _, dev := range devs {
		group := byDev[dev]
		floor, target, ok := a.volumeLimits(group[0].Folder, cfg)
		if !ok {
			continue
		}
		free, e := a.FreeBytes(group[0].Folder)
		if e != nil {
			return nil, e
		}
		if estimate {
			for _, p := range chosen {
				if s, e := os.Stat(p.V.Folder); e == nil && device(s) == dev && p.V.Size != nil {
					free += *p.V.Size
				}
			}
		}
		if free >= floor {
			continue
		}
		ordered := append([]*Verdict(nil), group...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].LastUsed < ordered[j].LastUsed })
		for _, v := range ordered {
			if estimate && free >= target {
				break
			}
			if v.Safe && !picked[v] && v.Size != nil && *v.Size != 0 {
				why := fmt.Sprintf("low space (%s free < floor %s), LRU", humanBytes(&free), humanBytes(&floor))
				chosen = append(chosen, Planned{v, why})
				picked[v] = true
				if estimate {
					free += *v.Size
				}
			}
		}
	}
	return chosen, nil
}

func (a *App) sweep(args Args, cfg *Config) int {
	if args.Floor != nil {
		cfg.Floor = *args.Floor
		cfg.Target = max(cfg.Target, cfg.Floor)
	}
	if args.Target != nil {
		cfg.Target = max(*args.Target, cfg.Floor)
	}
	armed, mode := false, ""
	if args.DryRun {
		mode = "dry-run (forced)"
	} else if cfg.MaintenanceOnly {
		mode = "dry-run (maintenance only)"
	} else if args.Armed {
		armed = exists(a.ArmedFile)
		mode = "armed (manual)"
		if !armed {
			mode = "dry-run: --armed needs `reclaimable arm` first"
		}
	} else {
		armed, mode = a.armedState()
		if !armed {
			mode = "dry-run (" + mode + ")"
		}
	}
	unlock, e := a.stateLock()
	if e != nil {
		return a.fail(e, 1)
	}
	defer unlock()
	reg, e := a.loadRegistry()
	if e != nil {
		return a.fail(e, 1)
	}
	folders, e := a.discover(cfg, reg, args.Scan, nil)
	if e != nil {
		return a.fail(e, 1)
	}
	vs := make([]*Verdict, 0, len(folders))
	for _, f := range folders {
		vs = append(vs, a.evaluate(f, cfg, reg, true))
	}
	actions, e := a.planChecked(vs, cfg, !armed)
	if e != nil {
		return a.fail(e, 1)
	}
	done := []map[string]any{}
	acted := map[*Verdict]bool{}
	var freed, would int64
	for _, p := range actions {
		v := p.V
		acted[v] = true
		verb := "delete"
		if v.Action == "move" {
			verb = "move"
		}
		pressure := strings.HasPrefix(p.Why, "low space")
		if armed && pressure {
			_, target, limited := a.volumeLimits(v.Folder, cfg)
			if limited {
				real, err := a.FreeBytes(v.Folder)
				if err != nil {
					return a.fail(err, 1)
				}
				if max(real, 0) >= target {
					line := fmt.Sprintf("skip %s: free space target reached (%s free >= %s)", v.Folder, humanBytes(&real), humanBytes(&target))
					if err := a.log(line); err != nil {
						return a.fail(err, 1)
					}
					fmt.Fprintln(a.Out, line)
					row := a.row(v)
					row["why"], row["done"], row["detail"] = p.Why, false, "target reached"
					done = append(done, row)
					if v.Size != nil {
						would += *v.Size
					}
					continue
				}
			}
		}
		ok, detail := a.removeFolder(v, armed, cfg, reg, pressure)
		prefix, action := "", verb
		if !armed {
			prefix = "[dry-run] "
		}
		if !ok {
			if armed {
				action += " SKIPPED"
			} else {
				action = "would " + verb
			}
		}
		tail := detail
		if !ok {
			tail = ""
			if detail != "dry-run" {
				tail = ": " + detail
			}
		}
		line := fmt.Sprintf("%s%s %s (%s) owner=%s kind=%s reason=%s%s", prefix, action, v.Folder, humanBytes(v.Size), v.Marker.Owner, v.Marker.effectiveKind(), p.Why, tail)
		if e := a.log(line); e != nil {
			return a.fail(e, 1)
		}
		fmt.Fprintln(a.Out, line)
		row := a.row(v)
		row["why"] = p.Why
		row["done"] = ok
		row["detail"] = detail
		done = append(done, row)
		if v.Size != nil {
			would += *v.Size
			if ok {
				freed += *v.Size
			}
		}
	}
	if e := a.writeExportList(reg, cfg); e != nil {
		return a.fail(e, 1)
	}
	if e := a.saveRegistry(reg); e != nil {
		return a.fail(e, 1)
	}
	blocked, kept := []map[string]any{}, []map[string]any{}
	for _, v := range vs {
		if !v.Safe {
			blocked = append(blocked, a.row(v))
		}
		if !acted[v] {
			kept = append(kept, a.row(v))
		}
	}
	maintenance, maintenanceFailed, e := a.runMaintenance(args, cfg)
	if e != nil {
		return a.fail(e, 1)
	}
	free, e := a.FreeBytes(a.Home)
	if e != nil {
		return a.fail(e, 1)
	}
	summary := map[string]any{"at": a.Now(), "host": a.Hostname(), "mode": mode, "armed": armed, "markers": len(vs), "free": free, "floor": cfg.Floor, "target": cfg.Target, "actions": done, "blocked": blocked, "kept": kept, "scan_complete": reg["last_scan_complete"]}
	if len(cfg.Maintenance) > 0 {
		summary["maintenance"] = maintenance
	}
	if e := writeJSON(a.LastSweep, summary); e != nil {
		return a.fail(e, 1)
	}
	quantity := "would free " + humanBytes(&would)
	if armed {
		quantity = "freed " + humanBytes(&freed)
	}
	tail := fmt.Sprintf("sweep %s: %d markers, %d actions, %s, %d kept, free %s (floor %s)", mode, len(vs), len(done), quantity, len(kept), humanBytes(&free), humanBytes(&cfg.Floor))
	if e := a.log(tail); e != nil {
		return a.fail(e, 1)
	}
	fmt.Fprintln(a.Out, tail)
	if args.Verbose {
		for _, v := range vs {
			if !acted[v] {
				fmt.Fprintf(a.Out, "  keep %s: %s\n", v.Folder, v.Reason)
			}
		}
	}
	if maintenanceFailed {
		return 1
	}
	return 0
}

func (a *App) cmdMark(args Args, cfg *Config) int {
	folder := a.resolveFolder(args.Path)
	if deny := a.denyReason(folder, cfg); deny != "" {
		fmt.Fprintf(a.Err, "reclaimable: refusing to mark %s: %s\n", folder, deny)
		return 2
	}
	if args.TTL != nil && *args.TTL != "" {
		if _, e := parseTTL(*args.TTL); e != nil {
			return a.fail(e, 2)
		}
	}
	if e := os.MkdirAll(folder, 0755); e != nil {
		return a.fail(e, 1)
	}
	m, e := a.readMarker(folder)
	if e != nil {
		var pe *os.PathError
		if errors.As(e, &pe) && !os.IsNotExist(e) {
			return a.fail(e, 1)
		}
		if !os.IsNotExist(e) {
			fmt.Fprintf(a.Err, "reclaimable: replacing invalid marker (%s)\n", e)
		}
		m = &Marker{Folder: folder, Owner: args.Owner, Holds: []map[string]any{}, Extra: map[string]any{}}
	}
	m.Owner = args.Owner
	for _, field := range [][2]*string{{args.TTL, &m.TTL}, {args.Kind, &m.Kind}, {args.Job, &m.Job}, {args.Session, &m.Session}, {args.MoveTo, &m.MoveTo}} {
		if field[0] != nil {
			*field[1] = *field[0]
		}
	}
	if args.Regen != nil {
		m.Regenerate = *args.Regen
	}
	if m.Regenerate == "" {
		fmt.Fprintln(a.Err, "reclaimable: --regen is required for a new marker")
		return 2
	}
	if e := a.writeMarker(m); e != nil {
		return a.fail(e, 1)
	}
	if e := a.register(folder); e != nil {
		return a.fail(e, 1)
	}
	fmt.Fprintf(a.Out, "marked %s owner=%s kind=%s ttl=%s\n", folder, m.Owner, m.effectiveKind(), a.markerTTL(m))
	return 0
}
func (a *App) cmdTouch(args Args) int {
	rc := 0
	for _, raw := range args.Paths {
		marker := filepath.Join(a.resolveFolder(raw), markerName)
		if !isFile(marker) {
			fmt.Fprintf(a.Err, "reclaimable: no marker in %s\n", filepath.Dir(marker))
			rc = 1
			continue
		}
		now := time.Unix(0, int64(a.Now()*1e9))
		if e := os.Chtimes(marker, now, now); e != nil {
			return a.fail(e, 1)
		}
	}
	return rc
}
func sameHoldSubpath(a *App, value any, want string) bool {
	path, ok := value.(string)
	return ok && a.pathKey(path) == a.pathKey(want)
}
func (a *App) cmdHold(args Args, release bool) int {
	folder := a.resolveFolder(args.Path)
	unlock, e := a.HoldLock()
	if e != nil {
		return a.fail(e, 1)
	}
	defer unlock()
	m, e := a.readMarker(folder)
	if e != nil {
		fmt.Fprintf(a.Err, "reclaimable: %s: %s\n", folder, e)
		return 1
	}
	sub := ""
	if args.Subpath != nil && *args.Subpath != "" {
		sub = a.expand(*args.Subpath)
	}
	job := ""
	if args.Job != nil {
		job = *args.Job
	}
	holds := []map[string]any{}
	for _, h := range m.Holds {
		same := h["job"] == job
		if release {
			same = same && (sub == "" || sameHoldSubpath(a, h["path"], sub))
		} else {
			same = same && ((sub == "" && h["path"] == nil) || sub != "" && sameHoldSubpath(a, h["path"], sub))
		}
		if !same {
			holds = append(holds, h)
		}
	}
	verb := "held"
	if release {
		verb = "released"
		if len(holds) == len(m.Holds) {
			fmt.Fprintf(a.Err, "reclaimable: %s holds nothing in %s\n", job, folder)
			return 1
		}
	} else {
		h := map[string]any{"job": job, "at": a.Now()}
		if sub != "" {
			h["path"] = sub
		}
		holds = append(holds, h)
	}
	m.Holds = holds
	if e := a.writeMarker(m); e != nil {
		return a.fail(e, 1)
	}
	fmt.Fprintf(a.Out, "%s %s for %s (%d holds)\n", verb, folder, job, len(m.Holds))
	return 0
}
func (a *App) cmdLS(args Args, cfg *Config) int {
	roots := []string{}
	for _, r := range args.Roots {
		roots = append(roots, a.expand(r))
	}
	unlock, e := a.stateLock()
	if e != nil {
		return a.fail(e, 1)
	}
	reg, e := a.loadRegistry()
	if e != nil {
		unlock()
		return a.fail(e, 1)
	}
	folders, e := a.discover(cfg, reg, args.Scan, roots)
	if e != nil {
		unlock()
		return a.fail(e, 1)
	}
	vs := []*Verdict{}
	for _, f := range folders {
		vs = append(vs, a.evaluate(f, cfg, reg, !args.Quick))
	}
	e = a.saveRegistry(reg)
	if e == nil {
		e = a.writeExportList(reg, cfg)
	}
	unlock()
	if e != nil {
		return a.fail(e, 1)
	}
	if args.JSON {
		rows := []map[string]any{}
		for _, v := range vs {
			rows = append(rows, a.row(v))
		}
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if e := enc.Encode(rows); e != nil {
			return a.fail(e, 1)
		}
		return 0
	}
	if len(vs) == 0 {
		fmt.Fprintln(a.Out, "no .reclaimable markers")
		return 0
	}
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].LastUsed < vs[j].LastUsed })
	for _, v := range vs {
		state := "kept"
		if v.Safe {
			state = "safe"
			if v.Expired {
				state = "ELIGIBLE"
			}
		}
		owner, kind, ttl := "?", "?", "?"
		if v.Marker != nil {
			owner = v.Marker.Owner
			kind = v.Marker.effectiveKind()
			ttl = a.markerTTL(v.Marker)
		}
		if owner == "" {
			owner = "?"
		}
		r := []rune(owner)
		if len(r) > 14 {
			owner = string(r[:14])
		}
		age := 0.0
		if v.LastUsed != 0 {
			age = a.Now() - v.LastUsed
		}
		fmt.Fprintf(a.Out, "%-8s %9s  %6s / %-4s %-14s %-8s %s  (%s)\n", state, humanBytes(v.Size), humanAge(age), ttl, owner, kind, strings.Replace(v.Folder, a.Home, "~", 1), v.Reason)
	}
	return 0
}
func (a *App) cmdStatus(args Args, cfg *Config) int {
	_, mode := a.armedState()
	lastRaw, e := loadJSON(a.LastSweep, nil)
	if e != nil {
		return a.fail(e, 1)
	}
	last := dict(lastRaw)
	free, e := a.FreeBytes(a.Home)
	if e != nil {
		return a.fail(e, 1)
	}
	fmt.Fprintf(a.Out, "host %s  %s  free %s  floor %s  target %s\n", a.Hostname(), mode, humanBytes(&free), humanBytes(&cfg.Floor), humanBytes(&cfg.Target))
	raw, e := loadJSON(a.Registry, map[string]any{"markers": map[string]any{}})
	if e != nil {
		return a.fail(e, 1)
	}
	reg := dict(raw)
	if reg == nil {
		return a.fail(fmt.Errorf("registry is not a JSON object"), 1)
	}
	when := "never"
	if truth(reg["last_scan"]) {
		when = humanAge(a.Now()-number(reg["last_scan"])) + " ago"
	}
	suffix := ""
	if v, ok := reg["last_scan_complete"]; ok && !truth(v) {
		suffix = " (depth/time-limited; marked folders are always registered)"
	}
	fmt.Fprintf(a.Out, "registered markers: %d  last scan: %s%s\n", len(dict(reg["markers"])), when, suffix)
	if last != nil && last["at"] != nil {
		actions, _ := last["actions"].([]any)
		kept, ok := last["kept"].([]any)
		if !ok {
			kept, _ = last["blocked"].([]any)
		}
		fmt.Fprintf(a.Out, "last sweep %s ago (%s): %v markers, %d actions, %d kept\n", humanAge(a.Now()-number(last["at"])), textValue(last["mode"]), last["markers"], len(actions), len(kept))
	} else {
		fmt.Fprintln(a.Out, "no sweep yet")
	}
	if exists(a.LogFile) {
		b, e := os.ReadFile(a.LogFile)
		if e != nil {
			return a.fail(e, 1)
		}
		fmt.Fprintf(a.Out, "--- %s (last %d)\n", strings.Replace(a.LogFile, a.Home, "~", 1), args.Lines)
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		start := len(lines) - args.Lines
		if args.Lines == 0 {
			start = 0
		}
		if args.Lines < 0 {
			start = -args.Lines
		}
		start = min(max(start, 0), len(lines))
		for _, line := range lines[start:] {
			fmt.Fprintln(a.Out, line)
		}
	}
	return 0
}
func (a *App) cmdArm(args Args) int {
	if args.Off {
		if e := os.Remove(a.ArmedFile); e != nil && !os.IsNotExist(e) {
			return a.fail(e, 1)
		}
		if e := a.log("disarmed"); e != nil {
			return a.fail(e, 1)
		}
		fmt.Fprintln(a.Out, "disarmed: sweeps are dry-run")
		return 0
	}
	if exists(a.ArmedFile) {
		_, mode := a.armedState()
		fmt.Fprintln(a.Out, mode)
		return 0
	}
	if e := writeJSON(a.ArmedFile, map[string]any{"armed_at": a.Now(), "host": a.Hostname()}); e != nil {
		return a.fail(e, 1)
	}
	if e := a.log("armed (first 24h stay dry-run)"); e != nil {
		return a.fail(e, 1)
	}
	fmt.Fprintln(a.Out, "armed; scheduled sweeps stay dry-run for the first 24h")
	return 0
}
