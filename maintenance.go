package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Maintenance commands are a config-only allow-list. No marker value is ever
// substituted into an argv or consulted when deciding what to execute.
type Maintenance struct {
	Name                       string
	Command                    []string
	Every, Timeout             float64
	WhenFreeBelow              *int64
	Lockfiles, Lsof, Processes []string
	BusyHolders                []map[string]any
}

type MaintenanceRecord struct {
	Name       string   `json:"name"`
	Command    []string `json:"command"`
	At         float64  `json:"at"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail"`
	Duration   float64  `json:"duration_s"`
	ExitStatus *int     `json:"exit_status"`
	TimedOut   bool     `json:"timed_out"`
	FreeBefore *int64   `json:"free_before"`
	FreeAfter  *int64   `json:"free_after"`
	FreedBytes *int64   `json:"freed_bytes"`
	FreedGB    *float64 `json:"freed_gb"`
}

func maintenanceExecutableName(name string) error {
	if strings.TrimSpace(name) == "" || strings.ContainsRune(name, 0) {
		return fmt.Errorf("maintenance executable must be nonempty and contain no NUL")
	}
	if strings.ContainsRune(name, filepath.Separator) && !filepath.IsAbs(name) {
		return fmt.Errorf("maintenance executable %q must be a bare name or an absolute path", name)
	}
	return nil
}

// Pin PATH results before changing cwd or handing an argv to a runner. Stat
// follows executable symlinks, but their targets must be regular files.
func maintenanceExecutable(name string) (string, error) {
	if err := maintenanceExecutableName(name); err != nil {
		return "", err
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("maintenance executable did not resolve to an absolute path")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("maintenance executable %q is not a regular executable file", path)
	}
	return path, nil
}

func (a *App) runMaintenanceProbe(argv []string, timeout float64, cwd string, env []string) Result {
	if len(argv) == 0 {
		return Result{Code: -1, Err: fmt.Errorf("empty maintenance probe command")}
	}
	executable, err := maintenanceExecutable(argv[0])
	if err != nil {
		return Result{Code: -1, Err: err}
	}
	return a.Run(append([]string{executable}, argv[1:]...), timeout, cwd, env)
}

func maintenanceDuration(v any, field string) (float64, error) {
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("maintenance %s must be a duration string", field)
	}
	n, err := parseTTL(s)
	if err != nil || n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) || n >= float64(math.MaxInt64)/float64(time.Second) {
		return 0, fmt.Errorf("maintenance %s must be a positive, bounded duration", field)
	}
	return n, nil
}
func knownKeys(m map[string]any, allowed ...string) error {
	for k := range m {
		if !contains(allowed, k) {
			return fmt.Errorf("unknown maintenance key %q", k)
		}
	}
	return nil
}
func parseMaintenance(raw map[string]any, holders []map[string]any, configFile string) ([]Maintenance, bool, error) {
	armed := false
	if v, exists := raw["maintenance_armed"]; exists {
		var ok bool
		armed, ok = v.(bool)
		if !ok {
			return nil, false, fmt.Errorf("maintenance_armed must be true or false")
		}
	}
	globalBusy, err := stringsKey(raw, "busy_holders")
	if err != nil {
		return nil, false, err
	}
	v, exists := raw["maintenance"]
	if !exists {
		return nil, armed, nil
	}
	tables, ok := listAny(v)
	if !ok {
		return nil, false, fmt.Errorf("maintenance must be an array of tables")
	}
	out := []Maintenance{}
	names := map[string]bool{}
	for _, table := range tables {
		m := dict(table)
		if m == nil {
			return nil, false, fmt.Errorf("maintenance entries must be tables")
		}
		if err := knownKeys(m, "name", "command", "every", "timeout", "when_free_below", "in_use", "busy_holders"); err != nil {
			return nil, false, err
		}
		name, ok := m["name"].(string)
		if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n\x00") || names[name] {
			return nil, false, fmt.Errorf("maintenance needs unique nonempty names")
		}
		names[name] = true
		cmd, err := command(m, "maintenance "+name)
		if err != nil {
			return nil, false, err
		}
		for _, arg := range cmd {
			if strings.ContainsRune(arg, 0) {
				return nil, false, fmt.Errorf("maintenance argv contains NUL")
			}
		}
		cmd[0] = expandConfigDir(cmd[0], configFile)
		if err := maintenanceExecutableName(cmd[0]); err != nil {
			return nil, false, err
		}
		every, err := maintenanceDuration(m["every"], "every")
		if err != nil {
			return nil, false, err
		}
		timeout := 1200.0
		if v, exists := m["timeout"]; exists {
			timeout, err = maintenanceDuration(v, "timeout")
			if err != nil {
				return nil, false, err
			}
		}
		h := Maintenance{Name: name, Command: cmd, Every: every, Timeout: timeout}
		if v, exists := m["when_free_below"]; exists {
			s, ok := v.(string)
			if !ok {
				return nil, false, fmt.Errorf("when_free_below must be a size string")
			}
			n, err := parseSize(s)
			if err != nil {
				return nil, false, err
			}
			h.WhenFreeBelow = &n
		}
		if v, exists := m["in_use"]; exists {
			inUse := dict(v)
			if inUse == nil {
				return nil, false, fmt.Errorf("in_use must be a table")
			}
			if err := knownKeys(inUse, "lockfiles", "lsof", "processes"); err != nil {
				return nil, false, err
			}
			for key, dest := range map[string]*[]string{"lockfiles": &h.Lockfiles, "lsof": &h.Lsof, "processes": &h.Processes} {
				*dest, err = stringsKey(inUse, key)
				if err != nil {
					return nil, false, err
				}
				for _, s := range *dest {
					if strings.TrimSpace(s) == "" || strings.ContainsRune(s, 0) {
						return nil, false, fmt.Errorf("in_use entries must be nonempty")
					}
				}
			}
		}
		refs, err := stringsKey(m, "busy_holders")
		if err != nil {
			return nil, false, err
		}
		refs = append(append([]string{}, globalBusy...), refs...)
		for _, ref := range refs {
			var matches []map[string]any
			for _, holder := range holders {
				if holder["name"] == ref {
					matches = append(matches, holder)
				}
			}
			if len(matches) != 1 {
				return nil, false, fmt.Errorf("busy holder %q must name exactly one command holder", ref)
			}
			holder := matches[0]
			cmd, err := command(holder, "busy holder "+ref)
			if err != nil {
				return nil, false, err
			}
			if err := maintenanceExecutableName(expandConfigDir(cmd[0], configFile)); err != nil {
				return nil, false, fmt.Errorf("busy holder %q: %w", ref, err)
			}
			// Holders use seconds, unlike maintenance's duration strings.
			if v, exists := holder["timeout"]; exists {
				n := number(v)
				if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) || n >= float64(math.MaxInt64)/float64(time.Second) {
					return nil, false, fmt.Errorf("invalid busy holder timeout")
				}
			}
			h.BusyHolders = append(h.BusyHolders, holder)
		}
		out = append(out, h)
	}
	return out, armed, nil
}

func (a *App) maintenanceInUse(h Maintenance) string {
	// Existence is deliberately conservative: stale lockfiles also veto cleanup.
	for _, raw := range h.Lockfiles {
		p := a.expand(raw)
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			if err != nil {
				return "lockfile check failed: " + err.Error()
			}
			return "lockfile exists: " + p
		}
	}
	for _, raw := range h.Lsof {
		p := a.expand(raw)
		if st, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "lsof path check failed: " + err.Error()
		} else if !st.IsDir() {
			return "lsof path is not a directory: " + p
		}
		r := a.runMaintenanceProbe([]string{"lsof", "-w", "-n", "-P", "-F", "pcn", "+D", p}, 90, "", nil)
		if r.Timeout || r.Err != nil || r.Code != 1 || strings.TrimSpace(r.Stdout) != "" || strings.TrimSpace(r.Stderr) != "" {
			return "lsof busy or check failed: " + p
		}
	}
	for _, name := range h.Processes {
		r := a.runMaintenanceProbe([]string{"pgrep", "-x", "--", regexp.QuoteMeta(name)}, 15, "", nil)
		if r.Timeout || r.Err != nil || r.Code != 1 || strings.TrimSpace(r.Stdout) != "" || strings.TrimSpace(r.Stderr) != "" {
			return "process busy or check failed: " + name
		}
	}
	for _, holder := range h.BusyHolders {
		cmd, err := command(holder, "maintenance busy holder")
		if err != nil {
			return err.Error()
		}
		if err := maintenanceExecutableName(expandConfigDir(cmd[0], a.ConfigFile)); err != nil {
			return err.Error()
		}
		if reason := a.commandHoldWithRunner(holder, &Marker{Folder: a.Home, Owner: h.Name, Kind: "cache"}, a.runMaintenanceProbe); reason != "" {
			return reason
		}
	}
	return ""
}

// Only an executable returned by this config-driven check may be run. Slow
// probes happen before measuring free space and re-reading the armed state.
func (a *App) inspectMaintenance(args Args, cfg *Config, h Maintenance, last map[string]any) (MaintenanceRecord, string) {
	row := MaintenanceRecord{Name: h.Name, Command: h.Command, At: a.Now(), Status: "skipped"}
	if !args.ForceDue && last != nil && a.Now()-number(last["at"]) < h.Every {
		row.Detail = "not due"
		return row, ""
	}
	executable, err := maintenanceExecutable(expandConfigDir(h.Command[0], a.ConfigFile))
	if err != nil {
		row.Detail = "executable unavailable: " + err.Error()
		return row, ""
	}
	if reason := a.maintenanceInUse(h); reason != "" {
		row.Detail = reason
		return row, ""
	}
	before, err := a.FreeBytes(a.Home)
	if err != nil || before < 0 {
		row.Detail = "free-space check failed"
		return row, ""
	}
	row.FreeBefore = &before
	if h.WhenFreeBelow != nil && before >= *h.WhenFreeBelow {
		row.Detail = "free space above trigger"
		return row, ""
	}
	armed, mode := a.armedState()
	if (!armed && !cfg.MaintenanceOnly) || !cfg.MaintenanceArmed || args.DryRun {
		row.Status, row.Detail = "dry-run", "would run"
		if !armed && !cfg.MaintenanceOnly {
			row.Detail += ": " + mode
		} else if !cfg.MaintenanceArmed {
			row.Detail += ": maintenance_armed is false"
		}
		return row, ""
	}
	row.At = a.Now()
	return row, executable
}

// Called only while state.lock is held, after all folder removals in a sweep.
func (a *App) runMaintenance(args Args, cfg *Config) ([]MaintenanceRecord, bool, error) {
	rows := []MaintenanceRecord{}
	if args.Only != "" {
		found := false
		for _, h := range cfg.Maintenance {
			found = found || h.Name == args.Only
		}
		if !found {
			return rows, false, fmt.Errorf("unknown maintenance hook %q", args.Only)
		}
	}
	if len(cfg.Maintenance) == 0 {
		return rows, false, nil
	}
	statePath := filepath.Join(a.StateDir, "maintenance.json")
	raw, err := loadJSON(statePath, map[string]any{})
	if err != nil {
		return rows, false, fmt.Errorf("maintenance state: %w", err)
	}
	state := dict(raw)
	if state == nil {
		return rows, false, fmt.Errorf("maintenance state must be an object")
	}
	for name, v := range state {
		rec := dict(v)
		at, ok := rec["at"].(float64)
		if !ok || at <= 0 || math.IsNaN(at) || math.IsInf(at, 0) {
			return rows, false, fmt.Errorf("invalid maintenance timestamp for %q", name)
		}
	}
	failed := false
	for _, h := range cfg.Maintenance {
		if args.Only != "" && args.Only != h.Name {
			continue
		}
		row, executable := a.inspectMaintenance(args, cfg, h, dict(state[h.Name]))
		run := executable != ""
		if run {
			// Persist the attempt before starting, so interruption/failure respects cadence.
			row.Status, row.Detail = "running", "attempt recorded"
			state[h.Name] = row
			if err := writeJSON(statePath, state); err != nil {
				return rows, failed, err
			}
			if err := a.log(fmt.Sprintf("maintenance %q starting argv=%q", h.Name, h.Command)); err != nil {
				return rows, failed, err
			}
			argv := append([]string{executable}, h.Command[1:]...)
			start := time.Now()
			r := a.Run(argv, h.Timeout, a.Home, nil)
			row.Duration, row.ExitStatus, row.TimedOut = time.Since(start).Seconds(), &r.Code, r.Timeout
			row.Status, row.Detail = "success", "completed"
			if r.Timeout || r.Err != nil || r.Code != 0 {
				row.Status, row.Detail = "failed", "command failed"
				if r.Timeout {
					row.Detail = "timed out"
				} else if r.Err != nil {
					row.Detail = r.Err.Error()
				}
			}
			after, err := a.FreeBytes(a.Home)
			if err != nil || after < 0 {
				row.Status, row.Detail = "failed", "post-run free-space check failed"
			} else {
				freed := after - *row.FreeBefore
				decimalGB := float64(freed) / float64(gb)
				row.FreeAfter, row.FreedBytes, row.FreedGB = &after, &freed, &decimalGB
			}
			failed = failed || row.Status == "failed"
			state[h.Name] = row
			if err := writeJSON(statePath, state); err != nil {
				return rows, failed, err
			}
		}
		line := fmt.Sprintf("maintenance %q %s argv=%q: %s", h.Name, row.Status, h.Command, row.Detail)
		if run {
			freed := "unknown"
			if row.FreedGB != nil {
				freed = fmt.Sprintf("%.3f GB", *row.FreedGB)
			}
			line += fmt.Sprintf("; freed %s; duration %.3fs; exit %d; timeout=%t", freed, row.Duration, *row.ExitStatus, row.TimedOut)
		}
		if err := a.log(line); err != nil {
			return rows, failed, err
		}
		fmt.Fprintln(a.Out, line)
		rows = append(rows, row)
	}
	return rows, failed, nil
}

func (a *App) cmdMaintenance(args Args, cfg *Config) int {
	unlock, err := a.stateLock()
	if err != nil {
		return a.fail(err, 1)
	}
	defer unlock()
	// Validate the report before allowing a destructive command.
	raw, err := loadJSON(a.LastSweep, map[string]any{})
	if err != nil {
		return a.fail(err, 1)
	}
	summary := dict(raw)
	if summary == nil {
		return a.fail(fmt.Errorf("last sweep must be an object"), 1)
	}
	rows, failed, err := a.runMaintenance(args, cfg)
	if err != nil {
		return a.fail(err, 1)
	}
	summary["maintenance"], summary["maintenance_at"] = rows, a.Now()
	if err := writeJSON(a.LastSweep, summary); err != nil {
		return a.fail(err, 1)
	}
	if failed {
		return 1
	}
	return 0
}
