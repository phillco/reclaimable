package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func maintenanceChdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(dir))
	t.Cleanup(func() { must(t, os.Chdir(old)) })
}

func TestMaintenanceExecutablePaths(t *testing.T) {
	for _, executable := range []string{"./fixture-clean", "bin/fixture-clean", "fixture-clean", "absolute"} {
		t.Run(executable, func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			caller := filepath.Join(e.Root, "caller")
			must(t, os.MkdirAll(filepath.Join(caller, "bin"), 0755))
			maintenanceChdir(t, caller)
			// Allow LookPath to return a relative PATH result, even on Go versions
			// that normally reject it with ErrDot. The runner must still pin it.
			t.Setenv("GODEBUG", "execerrdot=0")
			t.Setenv("PATH", "bin")
			callerBin, homeBin := caller, e.A.Home
			if executable == "bin/fixture-clean" || executable == "fixture-clean" {
				callerBin, homeBin = filepath.Join(caller, "bin"), bin
			}
			fakeExecutable(t, callerBin, "fixture-clean", "echo caller > \"$1.caller\"\n")
			fakeExecutable(t, homeBin, "fixture-clean", "echo home > \"$1.home\"\n")
			if executable == "absolute" {
				executable = filepath.Join(callerBin, "fixture-clean")
			}
			h := &e.Cfg.Maintenance[0]
			h.Command[0] = executable
			sentinel := h.Command[1]
			rows, _ := maintenanceRun(t, e, Args{})
			check(t, !exists(sentinel+".home"), "home executable ran: %+v", rows)
			allowed := filepath.IsAbs(executable) || executable == "fixture-clean"
			check(t, (rows[0].Status == "success") == allowed && exists(sentinel+".caller") == allowed, "wrong execution: %+v", rows)
			must(t, atomicWrite(e.A.ConfigFile, []byte(fmt.Sprintf("[[maintenance]]\nname = 'fixture'\ncommand = [%q]\nevery = '1h'\n", executable)), 0600))
			_, err := e.A.loadConfig(e.A.ConfigFile)
			check(t, (err == nil) == allowed, "wrong config validation for %q: %v", executable, err)
		})
	}
}

func TestMaintenancePinsExecutableBeforeProbes(t *testing.T) {
	e, bin := maintenanceFixture(t)
	other := t.TempDir()
	fakeExecutable(t, other, "fixture-clean", "echo home > \"$1.home\"\n")
	realRun := e.A.Run
	e.A.Run = func(argv []string, timeout float64, cwd string, env []string) Result {
		check(t, argv[0] == filepath.Join(bin, "fixture-clean") && cwd == e.A.Home, "unresolved hook: %q cwd=%q", argv, cwd)
		return realRun(argv, timeout, cwd, env)
	}
	e.A.FreeBytes = func(string) (int64, error) {
		t.Setenv("PATH", other)
		return 10 * gb, nil
	}
	rows, failed := maintenanceRun(t, e, Args{})
	check(t, !failed && rows[0].Status == "success" && !exists(e.Cfg.Maintenance[0].Command[1]+".home"), "hook resolved again: %+v", rows)
}

func TestMaintenanceProbeExecutablePaths(t *testing.T) {
	for _, probe := range []string{"lsof", "pgrep", "fixture-busy"} {
		t.Run(probe, func(t *testing.T) {
			e, homeBin := maintenanceFixture(t)
			caller := filepath.Join(e.Root, "caller")
			callerBin := filepath.Join(caller, "bin")
			must(t, os.MkdirAll(callerBin, 0755))
			maintenanceChdir(t, caller)
			t.Setenv("GODEBUG", "execerrdot=0")
			t.Setenv("PATH", "bin")
			sentinel := filepath.Join(e.Root, "probe")
			fakeExecutable(t, callerBin, probe, fmt.Sprintf("echo caller > %q\nexit 1\n", sentinel+".caller"))
			fakeExecutable(t, homeBin, probe, fmt.Sprintf("echo home > %q\nexit 1\n", sentinel+".home"))
			h := &e.Cfg.Maintenance[0]
			h.Command[0] = filepath.Join(homeBin, "fixture-clean")
			switch probe {
			case "lsof":
				h.Lsof = []string{e.Root}
			case "pgrep":
				h.Processes = []string{"fixture"}
			default:
				h.BusyHolders = []map[string]any{{"command": []string{probe}}}
			}
			realRun := e.A.Run
			e.A.Run = func(argv []string, timeout float64, cwd string, env []string) Result {
				// Resolve before handing off to any runner, not inside exec.Command.
				if filepath.Base(argv[0]) == probe {
					if !filepath.IsAbs(argv[0]) {
						t.Errorf("unresolved probe: %q", argv[0])
					}
					t.Setenv("PATH", homeBin)
					cwd = e.A.Home
				}
				return realRun(argv, timeout, cwd, env)
			}
			rows, _ := maintenanceRun(t, e, Args{})
			check(t, !exists(sentinel+".home"), "home probe executed: %+v", rows)
			check(t, rows[0].Status == "success" && exists(sentinel+".caller"), "probe did not use caller PATH: %+v", rows)
		})
	}
}

func TestMaintenanceRejectsRelativeBusyExecutable(t *testing.T) {
	e, _ := maintenanceFixture(t)
	maintenanceChdir(t, e.Root)
	fakeExecutable(t, e.Root, "fixture-busy", "echo ran > busy-ran\nexit 1\n")
	e.Cfg.Maintenance[0].BusyHolders = []map[string]any{{"command": []string{"./fixture-busy"}}}
	rows, _ := maintenanceRun(t, e, Args{})
	check(t, rows[0].Status == "skipped" && !exists(filepath.Join(e.Root, "busy-ran")), "relative busy holder executed: %+v", rows)
	config := "[[maintenance]]\nname = 'fixture'\ncommand = ['fixture-clean']\nevery = '1h'\nbusy_holders = ['busy']\n[[holder]]\nname = 'busy'\ncommand = ['./fixture-busy']\n"
	must(t, atomicWrite(e.A.ConfigFile, []byte(config), 0600))
	_, err := e.A.loadConfig(e.A.ConfigFile)
	check(t, err != nil, "relative busy executable accepted")
}

func TestMaintenanceExecutableMustBeRegularAndExecutable(t *testing.T) {
	for _, kind := range []string{"directory", "directory-link", "non-executable", "fifo"} {
		for _, busy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/busy=%t", kind, busy), func(t *testing.T) {
				e, _ := maintenanceFixture(t)
				path := filepath.Join(e.Root, "invalid")
				switch kind {
				case "directory":
					must(t, os.Mkdir(path, 0755))
				case "directory-link":
					must(t, os.Symlink(e.Root, path))
				case "non-executable":
					must(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0644))
				case "fifo":
					must(t, syscall.Mkfifo(path, 0755))
				}
				if busy {
					e.Cfg.Maintenance[0].BusyHolders = []map[string]any{{"command": []string{path}}}
				} else {
					e.Cfg.Maintenance[0].Command[0] = path
				}
				e.A.Run = func([]string, float64, string, []string) Result {
					t.Error("invalid executable reached runner")
					return Result{Code: 1}
				}
				rows, _ := maintenanceRun(t, e, Args{})
				check(t, rows[0].Status == "skipped", "invalid executable not refused: %+v", rows)
			})
		}
	}
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

func TestMaintenanceOnlySweep(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		only, optedIn, dry, immediate bool
		arm                           string
		runs                          bool
	}{
		{name: "unarmed", optedIn: true},
		{name: "unarmed-manual", optedIn: true, immediate: true},
		{name: "maintenance-only", only: true, optedIn: true, runs: true},
		{name: "opt-out", only: true},
		{name: "dry-run", only: true, optedIn: true, dry: true},
		{name: "armed", only: true, optedIn: true, arm: "ready", runs: true},
		{name: "armed-manual", only: true, optedIn: true, arm: "ready", immediate: true, runs: true},
		{name: "grace", only: true, optedIn: true, arm: "recent", runs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := maintenanceFixture(t)
			folder := e.make(t, "expired", 2*day, nil, nil)
			must(t, e.A.register(folder))
			config := fmt.Sprintf(`roots = [%q]
floor_gb = 0
target_gb = 0
maintenance_only = %t
maintenance_armed = %t
[[maintenance]]
name = "fixture"
command = ["fixture-clean", %q]
every = "24h"
`, filepath.Join(e.Root, "data"), tc.only, tc.optedIn, e.Cfg.Maintenance[0].Command[1])
			must(t, atomicWrite(e.A.ConfigFile, []byte(config), 0600))
			e.A.LoadConfig = func() (*Config, error) { return e.A.loadConfig(e.A.ConfigFile) }
			if tc.arm == "" {
				must(t, os.Remove(e.A.ArmedFile))
			} else if tc.arm == "recent" {
				must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now()}))
			}
			argv := []string{"sweep"}
			if tc.dry {
				argv = append(argv, "-n")
			}
			if tc.immediate {
				argv = append(argv, "-A")
			}
			check(t, e.A.main(argv) == 0, "sweep failed: %s", e.A.Err)
			check(t, exists(folder) && exists(filepath.Join(folder, "blob.bin")), "folder removed")
			check(t, exists(e.Cfg.Maintenance[0].Command[1]) == tc.runs, "unexpected hook execution: %s", e.A.Out)
			check(t, exists(filepath.Join(e.A.StateDir, "maintenance.json")) == tc.runs, "dry run consumed cadence")
			raw, err := loadJSON(e.A.LastSweep, nil)
			must(t, err)
			report := dict(raw)
			actions := report["actions"].([]any)
			check(t, report["armed"] == false && len(actions) == 1 && dict(actions[0])["done"] == false, "folder removal not dry-run: %+v", report)
			rows := report["maintenance"].([]any)
			check(t, len(rows) == 1 && (dict(rows[0])["status"] == "success") == tc.runs, "unexpected hook report: %+v", rows)
		})
	}
}

func TestMaintenanceOnlyGuards(t *testing.T) {
	for _, guard := range []string{"busy", "lockfile", "process", "lsof", "free-space", "cadence", "timeout", "manual-dry-run"} {
		t.Run(guard, func(t *testing.T) {
			e, bin := maintenanceFixture(t)
			must(t, os.Remove(e.A.ArmedFile))
			e.Cfg.MaintenanceOnly = true
			h := &e.Cfg.Maintenance[0]
			switch guard {
			case "busy":
				fakeExecutable(t, bin, "fixture-busy", "exit 0\n")
				h.BusyHolders = []map[string]any{{"command": []string{"fixture-busy"}}}
			case "lockfile":
				h.Lockfiles = []string{filepath.Join(e.Root, "cache.lock")}
				must(t, os.WriteFile(h.Lockfiles[0], nil, 0600))
			case "process":
				fakeExecutable(t, bin, "pgrep", "exit 0\n")
				h.Processes = []string{"fixture"}
			case "lsof":
				fakeExecutable(t, bin, "lsof", "exit 0\n")
				h.Lsof = []string{e.Root}
			case "free-space":
				h.WhenFreeBelow = intPtr(1)
			case "cadence":
				must(t, writeJSON(filepath.Join(e.A.StateDir, "maintenance.json"), map[string]any{"fixture": map[string]any{"at": e.A.Now()}}))
			case "timeout":
				fakeExecutable(t, bin, "fixture-clean", "sleep 1\necho ran > \"$1\"\n")
				h.Timeout = 0.02
			case "manual-dry-run":
				check(t, e.A.main([]string{"maintenance", "-n", "-f"}) == 0, "manual dry run failed")
				check(t, !exists(h.Command[1]), "manual dry run executed hook")
				return
			}
			rows, failed := maintenanceRun(t, e, Args{})
			check(t, !exists(h.Command[1]), "guard permitted cleanup: %+v", rows)
			if guard == "timeout" {
				check(t, failed && rows[0].TimedOut, "timeout not enforced: %+v", rows)
			} else {
				check(t, !failed && rows[0].Status == "skipped", "guard not preserved: %+v", rows)
			}
		})
	}
}

func TestMaintenanceOnlyConfig(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   bool
	}{
		{"", false},
		{"maintenance_only = true", true},
		{"maintenance_only = false", false},
		{"[hosts.fixture-host]\nmaintenance_only = true", true},
		{"maintenance_only = true\n[hosts.fixture-host]\nmaintenance_only = false", false},
		{"maintenance_only = false\n[hosts.fixture-host]\nmaintenance_only = true", true},
		{"[hosts.other-host]\nmaintenance_only = true", false},
	} {
		t.Run(tc.config, func(t *testing.T) {
			e := newTestEnv(t)
			must(t, atomicWrite(e.A.ConfigFile, []byte(tc.config), 0600))
			cfg, err := e.A.loadConfig(e.A.ConfigFile)
			must(t, err)
			check(t, cfg.MaintenanceOnly == tc.want && !cfg.MaintenanceArmed, "config: %+v", cfg)
		})
	}
	for _, prefix := range []string{"", "[hosts.fixture-host]\n"} {
		for _, value := range []string{`"true"`, "1", "[]", "{}"} {
			e := newTestEnv(t)
			must(t, atomicWrite(e.A.ConfigFile, []byte(prefix+"maintenance_only = "+value), 0600))
			_, err := e.A.loadConfig(e.A.ConfigFile)
			check(t, err != nil, "invalid maintenance_only accepted: %s%s", prefix, value)
		}
	}
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
