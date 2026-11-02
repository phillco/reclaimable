package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func maintenanceFixture(t *testing.T) (*testEnv, string) {
	t.Helper()
	e := newTestEnv(t)
	bin := filepath.Join(e.Root, "bin")
	must(t, os.MkdirAll(bin, 0755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	sentinel := filepath.Join(e.Root, "ran")
	fakeExecutable(t, bin, "fixture-clean", "echo ran >> \"$1\"\n")
	e.Cfg.Maintenance = []Maintenance{{Name: "fixture", Command: []string{"fixture-clean", sentinel}, Every: 3600, Timeout: 2}}
	e.Cfg.MaintenanceArmed = true
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	e.A.FreeBytes = func(string) (int64, error) { return 10 * gb, nil }
	return e, bin
}
func fakeExecutable(t *testing.T, bin, name, body string) {
	t.Helper()
	must(t, os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0755))
}
func maintenanceRun(t *testing.T, e *testEnv, args Args) ([]MaintenanceRecord, bool) {
	t.Helper()
	unlock, err := e.A.stateLock()
	must(t, err)
	defer unlock()
	rows, failed, err := e.A.runMaintenance(args, e.Cfg)
	must(t, err)
	return rows, failed
}
func TestMaintenanceCadenceAndForce(t *testing.T) {
	e, _ := maintenanceFixture(t)
	now := e.A.Now()
	e.A.Now = func() float64 { return now }
	rows, failed := maintenanceRun(t, e, Args{})
	check(t, !failed && rows[0].Status == "success", "first: %+v", rows)
	rows, _ = maintenanceRun(t, e, Args{})
	check(t, rows[0].Detail == "not due", "cadence: %+v", rows)
	rows, _ = maintenanceRun(t, e, Args{ForceDue: true})
	check(t, rows[0].Status == "success", "force: %+v", rows)
	now += 3600
	rows, _ = maintenanceRun(t, e, Args{})
	check(t, rows[0].Status == "success", "due: %+v", rows)
}
func TestMaintenanceArming(t *testing.T) {
	for _, mode := range []string{"unarmed", "grace", "bad-arm", "opt-out", "forced-dry", "enabled"} {
		t.Run(mode, func(t *testing.T) {
			e, _ := maintenanceFixture(t)
			switch mode {
			case "unarmed":
				must(t, os.Remove(e.A.ArmedFile))
			case "grace":
				must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now()}))
			case "bad-arm":
				must(t, os.WriteFile(e.A.ArmedFile, []byte("bad"), 0600))
			case "opt-out":
				e.Cfg.MaintenanceArmed = false
			}
			rows, _ := maintenanceRun(t, e, Args{DryRun: mode == "forced-dry", Armed: true, ForceDue: true})
			check(t, (rows[0].Status == "success") == (mode == "enabled"), "%s: %+v", mode, rows)
			check(t, exists(e.Cfg.Maintenance[0].Command[1]) == (mode == "enabled"), "unexpected execution")
			check(t, exists(filepath.Join(e.A.StateDir, "maintenance.json")) == (mode == "enabled"), "dry run consumed cadence")
		})
	}
}
func TestMaintenanceFreeTriggerAndMeasurement(t *testing.T) {
	e, _ := maintenanceFixture(t)
	e.Cfg.Maintenance[0].WhenFreeBelow = intPtr(10 * gb)
	rows, _ := maintenanceRun(t, e, Args{})
	check(t, rows[0].Detail == "free space above trigger", "equality must skip: %+v", rows)
	e.A.FreeBytes = func(string) (int64, error) { return 0, errors.New("unknown") }
	rows, _ = maintenanceRun(t, e, Args{ForceDue: true})
	check(t, rows[0].Status == "skipped", "unknown free: %+v", rows)
	calls := 0
	e.A.FreeBytes = func(string) (int64, error) {
		calls++
		if calls == 1 {
			return 5 * gb, nil
		}
		return 7 * gb, nil
	}
	check(t, e.A.main([]string{"maintenance"}) == 0, "manual failed: %s", e.A.Err)
	raw, err := loadJSON(e.A.LastSweep, nil)
	must(t, err)
	rowsJSON := dict(raw)["maintenance"].([]any)
	row := dict(rowsJSON[0])
	check(t, number(row["freed_bytes"]) == float64(2*gb) && number(row["freed_gb"]) == 2 && number(row["exit_status"]) == 0, "bad report: %+v", row)
	log, err := os.ReadFile(e.A.LogFile)
	must(t, err)
	check(t, bytes.Contains(log, []byte("freed 2.000 GB")) && bytes.Contains(log, []byte("duration")) && bytes.Contains(log, []byte("exit 0")), "bad log: %s", log)
}
func TestMaintenanceInUse(t *testing.T) {
	for _, probe := range []string{"lockfile", "lsof", "process"} {
		for _, code := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/%d", probe, code), func(t *testing.T) {
				e, bin := maintenanceFixture(t)
				h := &e.Cfg.Maintenance[0]
				switch probe {
				case "lockfile":
					p := filepath.Join(e.Root, "cache.lock")
					h.Lockfiles = []string{p}
					if code != 1 {
						must(t, os.WriteFile(p, nil, 0600))
					}
				case "lsof":
					h.Lsof = []string{e.Root}
					fakeExecutable(t, bin, "lsof", fmt.Sprintf("exit %d\n", code))
				case "process":
					h.Processes = []string{"fixture[worker]"}
					fakeExecutable(t, bin, "pgrep", fmt.Sprintf("[ \"$1\" = -x ] || exit 3\nexit %d\n", code))
				}
				rows, _ := maintenanceRun(t, e, Args{ForceDue: true})
				check(t, (rows[0].Status == "success") == (code == 1), "guard: %+v", rows)
			})
		}
	}
}
func TestMaintenanceWithoutInUse(t *testing.T) {
	e, bin := maintenanceFixture(t)
	config := fmt.Sprintf(`maintenance_armed = true
[[maintenance]]
name = "fixture"
command = ["fixture-clean", %q]
every = "24h"
`, e.Cfg.Maintenance[0].Command[1])
	must(t, atomicWrite(e.A.ConfigFile, []byte(config), 0600))
	cfg, err := e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	e.Cfg = cfg
	// No external probes are available; an omitted in_use must not need them.
	t.Setenv("PATH", bin)
	rows, failed := maintenanceRun(t, e, Args{})
	check(t, !failed && rows[0].Status == "success" && exists(e.Cfg.Maintenance[0].Command[1]), "hook without in_use did not run: %+v", rows)
}
func TestMaintenanceGuardErrors(t *testing.T) {
	for _, probe := range []string{"lsof", "pgrep"} {
		for _, output := range []string{"echo unexpected", "echo warning >&2", "sleep 1"} {
			t.Run(probe+output, func(t *testing.T) {
				e, bin := maintenanceFixture(t)
				fakeExecutable(t, bin, probe, output+"\nexit 1\n")
				if probe == "lsof" {
					e.Cfg.Maintenance[0].Lsof = []string{e.Root}
				} else {
					e.Cfg.Maintenance[0].Processes = []string{"fixture"}
				}
				realRun := e.A.Run
				e.A.Run = func(argv []string, timeout float64, cwd string, env []string) Result {
					return realRun(argv, 0.02, cwd, env)
				}
				rows, _ := maintenanceRun(t, e, Args{})
				check(t, rows[0].Status == "skipped", "guard failed open: %+v", rows)
			})
		}
	}
}
func TestMaintenanceBusyHolder(t *testing.T) {
	for _, code := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			fakeExecutable(t, bin, "fixture-busy", fmt.Sprintf("exit %d\n", code))
			e.Cfg.Maintenance[0].BusyHolders = []map[string]any{{"name": "scheduler", "command": []string{"fixture-busy"}, "timeout": 1}}
			rows, _ := maintenanceRun(t, e, Args{})
			check(t, (rows[0].Status == "success") == (code == 1), "busy: %+v", rows)
		})
	}
	for _, mode := range []string{"missing", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			if mode == "timeout" {
				fakeExecutable(t, bin, "fixture-busy", "sleep 2\nexit 1\n")
			}
			e.Cfg.Maintenance[0].BusyHolders = []map[string]any{{"command": []string{"fixture-busy"}, "timeout": 0.02}}
			rows, _ := maintenanceRun(t, e, Args{})
			check(t, rows[0].Status == "skipped", "busy error: %+v", rows)
		})
	}
}
func TestMaintenanceTimeoutAndFailureConsumeCadence(t *testing.T) {
	for _, body := range []string{"sleep 0.3; echo escaped > \"$1\"", "exit 7"} {
		t.Run(body, func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			fakeExecutable(t, bin, "fixture-clean", body+"\n")
			e.Cfg.Maintenance[0].Timeout = 0.03
			rows, failed := maintenanceRun(t, e, Args{})
			check(t, failed && rows[0].Status == "failed", "failure not recorded: %+v", rows)
			check(t, rows[0].TimedOut == strings.HasPrefix(body, "sleep"), "wrong timeout: %+v", rows)
			rows, _ = maintenanceRun(t, e, Args{})
			check(t, rows[0].Detail == "not due", "failure cadence: %+v", rows)
			time.Sleep(350 * time.Millisecond)
			check(t, !exists(e.Cfg.Maintenance[0].Command[1]), "timed-out group survived")
		})
	}
}
func TestMaintenanceMissingExecutableAndConfigOnly(t *testing.T) {
	e, _ := maintenanceFixture(t)
	f := e.make(t, "malicious", 0, nil, map[string]any{"command": []string{"fixture-clean", filepath.Join(e.Root, "injected")}, "maintenance": []any{map[string]any{"command": []string{"fixture-clean"}}}})
	must(t, e.A.register(f))
	e.Cfg.Maintenance = nil
	check(t, e.A.sweep(Args{}, e.Cfg) == 0, "sweep failed: %s", e.A.Err)
	check(t, !exists(filepath.Join(e.Root, "injected")), "marker executed")
	e.Cfg.Maintenance = []Maintenance{{Name: "missing", Command: []string{"fixture-missing-executable"}, Every: 10, Timeout: 1}}
	rows, _ := maintenanceRun(t, e, Args{})
	check(t, strings.Contains(rows[0].Detail, "executable unavailable"), "missing tool: %+v", rows)
}
func TestMaintenanceStateFailuresAndOnly(t *testing.T) {
	e, _ := maintenanceFixture(t)
	_, _, err := e.A.runMaintenance(Args{Only: "unknown"}, e.Cfg)
	check(t, err != nil, "unknown --only accepted")
	for _, data := range []string{"bad", "[]", `{"fixture":{}}`, `{"fixture":{"at":"yesterday"}}`} {
		must(t, atomicWrite(filepath.Join(e.A.StateDir, "maintenance.json"), []byte(data), 0600))
		_, _, err = e.A.runMaintenance(Args{ForceDue: true}, e.Cfg)
		check(t, err != nil, "bad state accepted: %s", data)
	}
	must(t, os.Remove(filepath.Join(e.A.StateDir, "maintenance.json")))
	must(t, os.MkdirAll(e.A.LogFile, 0755))
	_, _, err = e.A.runMaintenance(Args{}, e.Cfg)
	check(t, err != nil && !exists(e.Cfg.Maintenance[0].Command[1]), "log failure permitted cleanup")
}

func TestMaintenanceMissingProbesAndPostRunMeasurement(t *testing.T) {
	for _, probe := range []string{"lsof", "pgrep"} {
		t.Run(probe, func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			t.Setenv("PATH", bin)
			if probe == "lsof" {
				e.Cfg.Maintenance[0].Lsof = []string{e.Root}
			} else {
				e.Cfg.Maintenance[0].Processes = []string{"fixture"}
			}
			rows, _ := maintenanceRun(t, e, Args{ForceDue: true})
			check(t, rows[0].Status == "skipped", "missing probe ran: %+v", rows)
		})
	}
	e, _ := maintenanceFixture(t)
	calls := 0
	e.A.FreeBytes = func(string) (int64, error) {
		calls++
		if calls == 1 {
			return 5 * gb, nil
		}
		return 0, errors.New("measurement failed")
	}
	check(t, e.A.cmdMaintenance(Args{}, e.Cfg) == 1, "post-measurement failure exit")
	raw, err := loadJSON(e.A.LastSweep, nil)
	must(t, err)
	row := dict(dict(raw)["maintenance"].([]any)[0])
	check(t, row["status"] == "failed" && row["freed_bytes"] == nil, "invented freed bytes: %+v", row)
}

func TestMaintenanceStateWriteFailureAndSweepDryRun(t *testing.T) {
	e, _ := maintenanceFixture(t)
	state := filepath.Join(e.A.StateDir, "maintenance.json")
	// A directory cannot masquerade as the cadence state file.
	must(t, os.MkdirAll(state, 0755))
	_, _, err := e.A.runMaintenance(Args{}, e.Cfg)
	check(t, err != nil && !exists(e.Cfg.Maintenance[0].Command[1]), "bad state permitted cleanup")
	must(t, os.Remove(state))
	check(t, e.A.sweep(Args{DryRun: true}, e.Cfg) == 0, "sweep dry-run failed")
	check(t, !exists(e.Cfg.Maintenance[0].Command[1]), "sweep -n ran hook")
	// A valid but recent armed flag must stay dry even with sweep -A.
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now()}))
	check(t, e.A.sweep(Args{Armed: true}, e.Cfg) == 0, "manual sweep failed")
	check(t, !exists(e.Cfg.Maintenance[0].Command[1]), "sweep -A bypassed maintenance grace")
}

func TestMaintenancePreRunWriteFailure(t *testing.T) {
	e, _ := maintenanceFixture(t)
	e.A.FreeBytes = func(string) (int64, error) {
		// Introduce a write failure after the initial cadence read.
		must(t, os.MkdirAll(filepath.Join(e.A.StateDir, "maintenance.json"), 0755))
		return 5 * gb, nil
	}
	_, _, err := e.A.runMaintenance(Args{}, e.Cfg)
	check(t, err != nil && !exists(e.Cfg.Maintenance[0].Command[1]), "cadence write failure permitted cleanup")
}

func TestMaintenanceRefreshesArmingAfterGuard(t *testing.T) {
	e, bin := maintenanceFixture(t)
	fakeExecutable(t, bin, "fixture-busy", "/bin/rm -f \"$1\"\nexit 1\n")
	e.Cfg.Maintenance[0].BusyHolders = []map[string]any{{"command": []string{"fixture-busy", e.A.ArmedFile}}}
	rows, _ := maintenanceRun(t, e, Args{})
	check(t, rows[0].Status == "dry-run" && !exists(e.Cfg.Maintenance[0].Command[1]), "stale arming permitted cleanup: %+v", rows)
}

func TestMaintenanceCLISelectionAndPreservesSweep(t *testing.T) {
	e, _ := maintenanceFixture(t)
	for _, argv := range [][]string{{"maintenance", "--only="}, {"maintenance", "--only", ""}} {
		_, _, err := parseArgs(argv)
		check(t, err != nil, "empty selection accepted")
	}
	args, help, err := parseArgs([]string{"maintenance", "-n", "-o", "fixture", "-f"})
	must(t, err)
	check(t, !help && args.DryRun && args.Only == "fixture" && args.ForceDue, "flags: %+v", args)
	check(t, e.A.cmdMaintenance(args, e.Cfg) == 0, "initial maintenance failed")
	check(t, e.A.cmdStatus(Args{Lines: 1}, e.Cfg) == 0, "status after initial maintenance failed")
	check(t, strings.Contains(e.A.Out.(*bytes.Buffer).String(), "no sweep yet"), "maintenance invented a folder sweep: %s", e.A.Out)
	must(t, writeJSON(e.A.LastSweep, map[string]any{"at": 1234, "markers": 7, "actions": []any{"prior sweep"}}))
	check(t, e.A.cmdMaintenance(args, e.Cfg) == 0, "selected maintenance failed")
	raw, err := loadJSON(e.A.LastSweep, nil)
	must(t, err)
	check(t, number(dict(raw)["at"]) == 1234 && number(dict(raw)["markers"]) == 7, "manual run replaced sweep: %+v", raw)
	second := e.Cfg.Maintenance[0]
	second.Name = "other"
	second.Command = []string{"fixture-clean", filepath.Join(e.Root, "other")}
	e.Cfg.Maintenance = append(e.Cfg.Maintenance, second)
	rows, _ := maintenanceRun(t, e, Args{Only: "fixture"})
	check(t, len(rows) == 1 && rows[0].Name == "fixture" && !exists(second.Command[1]), "selection ran wrong hook: %+v", rows)
}
func TestMaintenanceSharesSweepLock(t *testing.T) {
	e, _ := maintenanceFixture(t)
	unlock, err := e.A.stateLock()
	must(t, err)
	done := make(chan int, 1)
	go func() { done <- e.A.cmdMaintenance(Args{}, e.Cfg) }()
	select {
	case <-done:
		unlock()
		t.Fatal("maintenance bypassed sweep lock")
	case <-time.After(30 * time.Millisecond):
	}
	check(t, !exists(e.Cfg.Maintenance[0].Command[1]), "ran under other lock")
	unlock()
	select {
	case code := <-done:
		check(t, code == 0, "maintenance exit %d", code)
	case <-time.After(3 * time.Second):
		t.Fatal("lock not released")
	}
}
func TestMaintenanceAfterFolderRemoval(t *testing.T) {
	e, bin := maintenanceFixture(t)
	folder := e.make(t, "expired", 2*day, nil, nil)
	must(t, e.A.register(folder))
	fakeExecutable(t, bin, "fixture-clean", "[ ! -d \"$2\" ] || exit 9\necho ran > \"$1\"\n")
	e.Cfg.Maintenance[0].Command = append(e.Cfg.Maintenance[0].Command, folder)
	check(t, e.A.sweep(Args{}, e.Cfg) == 0, "sweep failed: %s", e.A.Err)
	check(t, !exists(folder) && exists(e.Cfg.Maintenance[0].Command[1]), "order/removal failed")
	raw, err := loadJSON(e.A.LastSweep, nil)
	must(t, err)
	check(t, len(dict(raw)["maintenance"].([]any)) == 1, "report missing hook")
}
func TestMaintenanceConfig(t *testing.T) {
	base := `maintenance_armed = true
[[maintenance]]
name = "fixture"
command = ["fixture-clean", "literal {job}"]
every = "24h"
timeout = "20m"
when_free_below = "80GB"
in_use = { lockfiles = ["~/.cache/fixture/.lock"], lsof = ["~/.cache/fixture"], processes = ["fixture"] }
busy_holders = ["scheduler"]
[[holder]]
name = "scheduler"
command = ["fixture-busy"]
timeout = 3
`
	e, _ := maintenanceFixture(t)
	must(t, atomicWrite(e.A.ConfigFile, []byte(base), 0600))
	cfg, err := e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	check(t, cfg.MaintenanceArmed && len(cfg.Maintenance) == 1 && cfg.Maintenance[0].Every == day && len(cfg.Maintenance[0].BusyHolders) == 1, "config: %+v", cfg)
	commonBusy := "busy_holders = [\"scheduler\"]\n" + base
	must(t, atomicWrite(e.A.ConfigFile, []byte(commonBusy), 0600))
	cfg, err = e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	check(t, len(cfg.Maintenance[0].BusyHolders) == 2, "common busy check was omitted")
	must(t, atomicWrite(e.A.ConfigFile, []byte(commonBusy+"\n[hosts.fixture-host]\nbusy_holders = []\n"), 0600))
	cfg, err = e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	check(t, len(cfg.Maintenance[0].BusyHolders) == 1, "host common busy override failed")
	host := base + "\n[hosts.fixture-host]\nmaintenance_armed = false\nmaintenance = []\n"
	must(t, atomicWrite(e.A.ConfigFile, []byte(host), 0600))
	cfg, err = e.A.loadConfig(e.A.ConfigFile)
	must(t, err)
	check(t, !cfg.MaintenanceArmed && len(cfg.Maintenance) == 0, "host override: %+v", cfg)
	for _, pair := range [][2]string{{"maintenance_armed = true", `maintenance_armed = "true"`}, {`every = "24h"`, `every = "0s"`}, {`timeout = "20m"`, `timeout = "999999999999999999999999999999999999h"`}, {`command = ["fixture-clean", "literal {job}"]`, `command = "fixture-clean"`}, {`busy_holders = ["scheduler"]`, `busy_holders = ["missing"]`}, {`lockfiles = ["~/.cache/fixture/.lock"]`, `lockfiles = "bad"`}, {`processes = ["fixture"]`, `process = ["fixture"]`}} {
		must(t, atomicWrite(e.A.ConfigFile, []byte(strings.Replace(base, pair[0], pair[1], 1)), 0600))
		_, err = e.A.loadConfig(e.A.ConfigFile)
		check(t, err != nil, "invalid config accepted: %s", pair[1])
	}
}
