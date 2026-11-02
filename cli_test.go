package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVersionDoesNotLoadConfig(t *testing.T) {
	for _, flag := range []string{"-V", "--version"} {
		t.Run(flag, func(t *testing.T) {
			e := newTestEnv(t)
			e.A.LoadConfig = func() (*Config, error) {
				t.Fatal("version must not load configuration")
				return nil, nil
			}
			if code := e.A.main([]string{flag}); code != 0 {
				t.Fatalf("version exit code: %d", code)
			}
			if got := e.A.Out.(*bytes.Buffer).String(); got != "reclaimable "+version+"\n" {
				t.Fatalf("version output: %q", got)
			}
		})
	}
}

func oldMarker(t *testing.T, folder string, seconds float64) {
	t.Helper()
	at := time.Now().Add(-time.Duration(seconds * 1e9))
	must(t, os.Chtimes(filepath.Join(folder, markerName), at, at))
}
func TestMarkTouchCLIRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	folder := filepath.Join(e.Root, "data/new-cache")
	check(t, e.A.main([]string{"mark", folder, "-o", "tool", "-t", "24h", "-r", "tool rebuilds it"}) == 0, "mark failed")
	m, err := e.A.readMarker(folder)
	must(t, err)
	check(t, m.Owner == "tool" && m.Regenerate == "tool rebuilds it", "marker: %+v", m)
	reg, err := e.A.loadRegistry()
	must(t, err)
	check(t, mapEntry(reg, "markers")[folder] != nil, "folder not registered")
	oldMarker(t, folder, 5*day)
	check(t, e.A.main([]string{"touch", folder}) == 0, "touch failed")
	st, err := os.Stat(m.path())
	must(t, err)
	check(t, time.Since(st.ModTime()) < time.Minute, "not touched")
}
func TestSweepDryRunByDefaultAndArmedAfterGrace(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "old", 2*day, nil, map[string]any{"ttl": "24h"})
	args := Args{Scan: true}
	check(t, e.A.sweep(args, e.Cfg) == 0, "sweep failed")
	check(t, exists(f), "unarmed removed folder")
	b, err := os.ReadFile(e.A.LogFile)
	must(t, err)
	check(t, strings.Contains(string(b), "would delete"), "dry log %s", b)
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 3600}))
	check(t, e.A.sweep(args, e.Cfg) == 0, "sweep failed")
	check(t, exists(f), "grace removed folder")
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	check(t, e.A.sweep(args, e.Cfg) == 0, "sweep failed")
	check(t, !exists(f), "expired armed folder kept")
}
func TestSweepSummaryCountsEveryKeptFolder(t *testing.T) {
	e := newTestEnv(t)
	out := &bytes.Buffer{}
	e.A.Out = out
	e.make(t, "fresh", 60, nil, map[string]any{"ttl": "24h"})
	e.make(t, "held", 9*day, nil, map[string]any{"ttl": "1d", "holds": []map[string]any{{"job": "j"}}})
	e.make(t, "old", 9*day, nil, map[string]any{"ttl": "1d"})
	check(t, e.A.sweep(Args{Scan: true, Verbose: true}, e.Cfg) == 0, "sweep failed")
	check(t, strings.Contains(out.String(), "2 kept") && strings.Contains(out.String(), "keep "), "output %s", out)
	raw, err := loadJSON(e.A.LastSweep, nil)
	must(t, err)
	m := dict(raw)
	check(t, len(m["kept"].([]any)) == 2 && len(m["blocked"].([]any)) == 1, "summary %v", m)
}
func TestHoldsBlockAndRelease(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "held", 9*day, nil, nil)
	check(t, e.A.main([]string{"hold", f, "job42"}) == 0, "hold failed")
	oldMarker(t, f, 9*day)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "held by job42"), "verdict %+v", v)
	check(t, e.A.main([]string{"release", f, "job42"}) == 0, "release failed")
	oldMarker(t, f, 9*day)
	check(t, e.A.evaluate(f, e.Cfg, e.Reg, true).Safe, "released folder unsafe")
}
func TestMarkRefusesDenied(t *testing.T) {
	e := newTestEnv(t)
	check(t, e.A.main([]string{"mark", e.A.expand("~/.ssh/keys"), "-o", "t", "-r", "r"}) == 2, "denied mark succeeded")
}
func TestFloorTakesLRUSafeBeforeTTL(t *testing.T) {
	e := newTestEnv(t)
	a := e.make(t, "a", 10*3600, map[string][]byte{"x": bytes.Repeat([]byte("x"), 4096)}, map[string]any{"ttl": "3d"})
	b := e.make(t, "b", 3600, map[string][]byte{"x": bytes.Repeat([]byte("x"), 4096)}, map[string]any{"ttl": "3d"})
	c := e.make(t, "c", 20*3600, map[string][]byte{"x": bytes.Repeat([]byte("x"), 4096)}, map[string]any{"ttl": "3d"})
	check(t, e.A.main([]string{"hold", c, "reader"}) == 0, "hold failed")
	oldMarker(t, c, 20*3600)
	vs := []*Verdict{e.A.evaluate(a, e.Cfg, e.Reg, true), e.A.evaluate(b, e.Cfg, e.Reg, true), e.A.evaluate(c, e.Cfg, e.Reg, true)}
	for _, v := range vs {
		check(t, !v.Expired, "fresh expired")
	}
	e.Cfg.Floor, e.Cfg.Target = 1e18, 1e18
	e.A.Home = e.Root
	chosen := e.A.plan(vs, e.Cfg)
	check(t, len(chosen) == 2 && chosen[0].V.Folder == a && chosen[1].V.Folder == b, "chosen %+v", chosen)
	e.Cfg.Floor, e.Cfg.Target = 1, 1
	check(t, len(e.A.plan(vs, e.Cfg)) == 0, "floor unexpectedly chose folders")
}
func TestCLIParserAndManualArming(t *testing.T) {
	for _, args := range [][]string{{"mark", "x", "-o", "t", "-r", "r"}, {"mark", "-ot", "x", "--regen=r", "--ttl=3d"}, {"ls", "root", "-jqS"}, {"touch", "--", "-x"}, {"mark", "x", "-o", "-1"}, {"mark", "x", "--owner=-tool"}, {"status", "-l", "-1"}, {"touch", "-1"}} {
		_, help, err := parseArgs(args)
		check(t, err == nil && !help, "parse %v: %v", args, err)
	}
	for _, args := range [][]string{{}, {"nope"}, {"mark", "x"}, {"mark", "x", "-o", "t", "-k", "unknown"}, {"sweep", "-nA"}, {"sweep", "-f", "bad"}, {"arm", "extra"}, {"mark", "x", "-o", "--help"}, {"mark", "x", "-o", "--bad", "-r", "r"}} {
		_, _, err := parseArgs(args)
		check(t, err != nil, "invalid accepted: %v", args)
	}
	e := newTestEnv(t)
	f := e.make(t, "manual", 2*day, nil, map[string]any{"ttl": "1d"})
	check(t, e.A.main([]string{"sweep", "-AS"}) == 0 && exists(f), "manual sweep armed without flag")
	check(t, e.A.main([]string{"arm"}) == 0, "arm failed")
	check(t, e.A.main([]string{"sweep", "-nS"}) == 0 && exists(f), "forced dry run removed")
	check(t, e.A.main([]string{"sweep", "-AS"}) == 0 && !exists(f), "manual armed sweep failed")
	check(t, e.A.main([]string{"arm", "-x"}) == 0 && !exists(e.A.ArmedFile), "disarm failed")
}
func TestCLISubpathHoldsPreserveUnknownFields(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "subpaths", 0, nil, map[string]any{"custom": 1})
	for _, sub := range []string{"a/../b", "c"} {
		check(t, e.A.main([]string{"hold", f, "job", "-p", sub}) == 0, "hold failed")
	}
	check(t, e.A.main([]string{"hold", f, "job", "-p", "b"}) == 0, "dedup hold failed")
	m, err := e.A.readMarker(f)
	must(t, err)
	check(t, len(m.Holds) == 2 && number(m.Extra["custom"]) == 1, "marker %+v", m)
	check(t, e.A.main([]string{"release", f, "job", "-p", "b"}) == 0, "sub release failed")
	m, err = e.A.readMarker(f)
	must(t, err)
	check(t, len(m.Holds) == 1, "subpath release lost unrelated hold")
	check(t, e.A.main([]string{"release", f, "missing"}) == 1, "missing hold release succeeded")
	check(t, e.A.main([]string{"release", f, "job"}) == 0, "release all failed")
}

func TestCorruptArmedTimestampFailsClosed(t *testing.T) {
	e := newTestEnv(t)
	for _, at := range []any{"NaN", "+Inf", "-Inf", "Infinity", nil, []any{}, map[string]any{}} {
		must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": at}))
		armed, reason := e.A.armedState()
		check(t, !armed && strings.Contains(reason, "unreadable"), "invalid %v armed: %s", at, reason)
	}
}
func TestPlanFailureKeepsExpiredFolders(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "space-probe", 30*day, nil, nil)
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	e.A.FreeBytes = func(string) (int64, error) { return 0, os.ErrPermission }
	check(t, e.A.sweep(Args{Scan: true}, e.Cfg) == 1 && exists(f), "failed capacity probe permitted deletion")
	e.A.Home = filepath.Join(e.Root, "missing-home")
	check(t, len(e.A.plan([]*Verdict{e.A.evaluate(f, e.Cfg, e.Reg, true)}, e.Cfg)) == 0, "missing home permitted plan")
}

func TestRelativeVolumeFloorUsesAbsoluteMount(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "cache", 3600, nil, map[string]any{"ttl": "3d"})
	mount := f
	for !isMount(mount) && filepath.Dir(mount) != mount {
		mount = filepath.Dir(mount)
	}
	e.Cfg.Floor = 0
	e.Cfg.Target = 1000000000000000000
	e.Cfg.VolumeFloors = map[string]int64{mount: 1000000000000000000}
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(filepath.Dir(f)))
	defer os.Chdir(cwd)
	v := e.A.evaluate("cache", e.Cfg, e.Reg, true)
	check(t, v.Safe && !v.Expired, "%s", debugVerdict(v))
	p := e.A.plan([]*Verdict{v}, e.Cfg)
	check(t, len(p) == 1 && p[0].V == v, "relative mount missed configured floor")
}

func TestRelativeVolumeFloorsKeyIsAbsolute(t *testing.T) {
	e := newTestEnv(t)
	mount := e.Root
	for !isMount(mount) && filepath.Dir(mount) != mount {
		mount = filepath.Dir(mount)
	}
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(mount))
	defer os.Chdir(cwd)
	config := filepath.Join(e.Root, "volume-config.toml")
	must(t, os.WriteFile(config, []byte("volume_floors = { \".\" = \"10GB\", \"x/../y\" = \"1GB\" }\n"), 0600))
	cfg, err := e.A.loadConfig(config)
	must(t, err)
	check(t, len(cfg.VolumeFloors) == 2 && cfg.VolumeFloors[mount] == 10*gb && cfg.VolumeFloors[filepath.Join(mount, "y")] == gb, "relative volume keys: %v", cfg.VolumeFloors)
}
func TestPlanMatchesVolumeFloorByAbsoluteMount(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "vf", 3600, map[string][]byte{"x": bytes.Repeat([]byte("x"), 4096)}, map[string]any{"ttl": "3d"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	mount := f
	for !isMount(mount) && filepath.Dir(mount) != mount {
		mount = filepath.Dir(mount)
	}
	other, err := os.Stat("/")
	must(t, err)
	st, err := os.Stat(f)
	must(t, err)
	if device(other) == device(st) {
		t.Skip("home and data share a device here")
	}
	e.A.Home = "/"
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(mount))
	defer os.Chdir(cwd)
	e.Cfg.VolumeFloors = map[string]int64{e.A.expand("."): 1e18}
	chosen := e.A.plan([]*Verdict{v}, e.Cfg)
	check(t, len(chosen) == 1 && chosen[0].V.Folder == f, "absolute volume key did not select data volume: %+v", chosen)
}

func TestPlanUsesCanonicalVolumeFloor(t *testing.T) {
	for _, spelling := range []string{"MixedCase", "Cafe\u0301"} {
		t.Run(spelling, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, spelling+"/fresh", 3600, nil, map[string]any{"ttl": "3d"})
			mount := filepath.Dir(f)
			e.A.IsMount = func(p string) bool { return p == mount }
			key := "/SYSTEM/VOLUMES/DATA" + strings.ToUpper(strings.ReplaceAll(mount, "e\u0301", "é"))
			config := filepath.Join(e.Root, "volume-config.toml")
			must(t, os.WriteFile(config, []byte("volume_floors = { \""+key+"\" = \"100\" }\n"), 0600))
			cfg, err := e.A.loadConfig(config)
			must(t, err)
			e.Cfg.VolumeFloors = cfg.VolumeFloors
			e.Cfg.Floor, e.Cfg.Target = 1000*gb, 2000*gb
			v := e.A.evaluate(f, e.Cfg, e.Reg, true)
			check(t, v.Safe && !v.Expired, "fresh fixture: %s", debugVerdict(v))
			for _, estimate := range []bool{true, false} {
				for _, free := range []int64{150 * gb, 50 * gb} {
					e.A.FreeBytes = func(string) (int64, error) { return free, nil }
					chosen, err := e.A.planChecked([]*Verdict{v}, e.Cfg, estimate)
					must(t, err)
					want := 0
					if free < 100*gb {
						want = 1
					}
					check(t, len(chosen) == want, "free=%d estimate=%v selected %d fresh folders, want %d", free, estimate, len(chosen), want)
				}
			}
		})
	}
}
func TestPressureSweepStopsWhenRealFreeSpaceReachesTarget(t *testing.T) {
	e := newTestEnv(t)
	folders := []string{}
	for i, name := range []string{"pa", "pb", "pc"} {
		folders = append(folders, e.make(t, name, float64(10-i)*3600, map[string][]byte{"x": bytes.Repeat([]byte("x"), 4096)}, map[string]any{"ttl": "3d"}))
	}
	e.Cfg.Floor, e.Cfg.Target = 1e18, 1e18
	e.A.FreeBytes = func(string) (int64, error) {
		for _, f := range folders {
			if !exists(f) {
				return 1e18 + 1, nil
			}
		}
		return 5, nil
	}
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	floor, target := int64(1e18), int64(1e18)
	check(t, e.A.sweep(Args{Scan: true, Floor: &floor, Target: &target}, e.Cfg) == 0, "pressure sweep failed")
	kept := 0
	for _, f := range folders {
		if exists(f) {
			kept++
		}
	}
	check(t, kept == 2 && !exists(folders[0]), "only oldest should be removed: %d retained", kept)
}

func TestPressureSweepContinuesWhenEstimateOverstatesReclaimedSpace(t *testing.T) {
	e := newTestEnv(t)
	folders := []string{}
	for i, name := range []string{"oldest", "middle", "newest"} {
		folders = append(folders, e.make(t, name, float64(10-i)*3600, nil, map[string]any{"ttl": "3d"}))
	}
	e.Cfg.Floor, e.Cfg.Target = 100, 300
	e.A.FreeBytes = func(string) (int64, error) {
		removed := 0
		for _, f := range folders {
			if !exists(f) {
				removed++
			}
		}
		if removed >= 2 {
			return 300, nil
		}
		return 0, nil
	}
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	check(t, e.A.sweep(Args{Scan: true}, e.Cfg) == 0, "pressure sweep failed")
	check(t, !exists(folders[0]) && !exists(folders[1]) && exists(folders[2]), "allocation estimates prematurely stopped real pressure cleanup")
}
