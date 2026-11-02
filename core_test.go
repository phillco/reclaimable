package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkerParsingAndDefaults(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "c", 0, nil, map[string]any{"ttl": "3d", "kind": "cache", "custom": 1})
	m, err := e.A.readMarker(f)
	must(t, err)
	ttl, err := parseTTL(e.A.markerTTL(m))
	must(t, err)
	check(t, m.Owner == "test" && ttl == 3*day && number(m.Extra["custom"]) == 1, "bad parsed marker %+v", m)
	for _, c := range []struct {
		kind string
		ttl  float64
	}{{"staged", 2 * day}, {"", day}} {
		m, err = e.A.readMarker(e.make(t, "default-"+c.kind, 0, nil, map[string]any{"kind": nil}))
		if c.kind != "" {
			m, err = e.A.readMarker(e.make(t, "default-"+c.kind, 0, nil, map[string]any{"kind": c.kind}))
		}
		must(t, err)
		ttl, err = parseTTL(e.A.markerTTL(m))
		must(t, err)
		check(t, ttl == c.ttl, "kind %s TTL %v", c.kind, ttl)
	}
	must(t, e.A.writeMarker(m))
	_, err = e.A.readMarker(m.Folder)
	must(t, err)
}
func TestBadMarkersAreKept(t *testing.T) {
	for i, bad := range []map[string]any{{"owner": ""}, {"kind": "nope"}, {"ttl": "soon"}, {"holds": "x"}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := newTestEnv(t)
			v := e.A.evaluate(e.make(t, "bad", 99*day, nil, bad), e.Cfg, e.Reg, true)
			check(t, !v.Safe && strings.HasPrefix(v.Reason, "bad marker"), "%s", debugVerdict(v))
		})
	}
}
func TestTTLAndSizeParsing(t *testing.T) {
	for s, want := range map[string]float64{"24h": day, "1.5d": 1.5 * day} {
		got, err := parseTTL(s)
		must(t, err)
		check(t, got == want, "%s: got %v", s, got)
	}
	_, err := parseTTL("3 days")
	check(t, err != nil, "bad ttl accepted")
	for s, want := range map[string]int64{"50GiB": 50 * (1 << 30), "30": 30 * gb} {
		got, err := parseSize(s)
		must(t, err)
		check(t, got == want, "%s: %d", s, got)
	}
}
func TestFreshVsExpired(t *testing.T) {
	e := newTestEnv(t)
	fresh := e.A.evaluate(e.make(t, "fresh", 3600, nil, map[string]any{"ttl": "24h"}), e.Cfg, e.Reg, true)
	old := e.A.evaluate(e.make(t, "old", 2*day, nil, map[string]any{"ttl": "24h"}), e.Cfg, e.Reg, true)
	check(t, fresh.Safe && !fresh.Expired, "%s", debugVerdict(fresh))
	check(t, old.Safe && old.Expired && old.Action == "delete" && old.Size != nil && *old.Size > 0, "%s", debugVerdict(old))
}
func TestBuiltinDenyList(t *testing.T) {
	e := newTestEnv(t)
	for _, raw := range []string{"~/src/foo/.git", "~/src/foo/.jj/repo", "~", "/", "~/Documents", "~/.ssh/x", "/Volumes/Data", "~/Pictures/Photos.photoslibrary/x"} {
		t.Run(raw, func(t *testing.T) { check(t, e.A.denyReason(e.A.expand(raw), e.Cfg) != "", "allowed %s", raw) })
	}
}
func TestDenyAllowsOrdinaryCaches(t *testing.T) {
	e := newTestEnv(t)
	check(t, e.A.denyReason(e.A.expand("~/src/proj/cache/frames"), e.Cfg) == "", "ordinary cache denied")
}
func TestConfigOnlyAddsToDeny(t *testing.T) {
	e := newTestEnv(t)
	p := filepath.Join(e.Root, "c.toml")
	must(t, os.WriteFile(p, []byte("deny = [\"/tmp/extra-deny\"]\ndeny_names = [\"golden-*\"]\ndeny_exact = [\"~/mine\"]\ndeny_sequences = [[\"a\", \"b\"]]\nfloor = \"40GB\"\n"), 0644))
	cfg, err := e.A.loadConfig(p)
	must(t, err)
	for _, s := range denyPaths {
		check(t, contains(cfg.DenyPaths, s), "dropped default %s", s)
	}
	check(t, contains(cfg.DenyPaths, "/tmp/extra-deny") && contains(cfg.DenyNames, "golden-*") && contains(cfg.DenyNames, "*.photoslibrary"), "missing additive denies")
	check(t, cfg.Floor == 40*gb && cfg.Target == 60*gb, "wrong floor/target")
	for _, s := range []string{"~/mine", "/tmp/extra-deny/x", "~/x/golden-1"} {
		check(t, e.A.denyReason(e.A.expand(s), cfg) != "", "allowed %s", s)
	}
	check(t, e.A.denyReason(e.A.expand("~/x/a/b/c"), cfg) == "deny-listed name a/b", "sequence ignored")
}
func TestDeniedDescendantsBlock(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.DenyNames = append(e.Cfg.DenyNames, "models")
	f := e.make(t, "cachey", 9*day, map[string][]byte{"x/models/w.pth": []byte("1")}, nil)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "deny-listed"), "%s", debugVerdict(v))
}
func TestConfigFloorsHostsTTLsAndValidation(t *testing.T) {
	e := newTestEnv(t)
	e.A.Hostname = func() string { return "box-1" }
	p := filepath.Join(e.Root, "c.toml")
	must(t, os.WriteFile(p, []byte("floor_gb = 10\n[default_ttls]\ncache = \"6h\"\n[hosts.box-1]\nfloor = \"50GiB\"\ndeny = [\"/x\"]\n[hosts.other]\nfloor = \"1GB\"\n[[holder]]\ncommand = [\"true\"]\n[job_done]\ncommand = [\"true\", \"{job}\"]\n"), 0644))
	cfg, err := e.A.loadConfig(p)
	must(t, err)
	check(t, cfg.Floor == 50*(1<<30) && contains(cfg.DenyPaths, "/x") && e.A.DefaultTTL["cache"] == "6h" && cfg.JobDone != nil && len(cfg.Holders) == 1, "bad config %+v", cfg)
	e.A.Hostname = func() string { return "elsewhere" }
	cfg, err = e.A.loadConfig(p)
	must(t, err)
	check(t, cfg.Floor == 10*gb, "host override leaked")
	cfg, err = e.A.loadConfig(filepath.Join(e.Root, "missing.toml"))
	must(t, err)
	check(t, cfg.Floor == 30*gb, "wrong default floor")
	must(t, os.WriteFile(p, []byte("[[holder]]\nname = 'x'\n"), 0644))
	_, err = e.A.loadConfig(p)
	check(t, err != nil, "invalid holder accepted")
}
func TestExcludeListExport(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "c", 0, nil, nil)
	e.Cfg.ExportList = filepath.Join(e.Root, "out/list.txt")
	e.Cfg.ExportFormat = "path {path}"
	must(t, e.A.writeExportList(map[string]any{"markers": map[string]any{f: map[string]any{}}}, e.Cfg))
	b, err := os.ReadFile(e.Cfg.ExportList)
	must(t, err)
	check(t, strings.Contains(string(b), "path "+f), "bad export %s", b)
}
func TestScanDoesNotDescendIntoMarkedOrDenied(t *testing.T) {
	e := newTestEnv(t)
	outer := e.make(t, "outer", 0, nil, nil)
	e.make(t, "outer/inner", 0, nil, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/secret"))
	e.make(t, "secret/hidden", 0, nil, nil)
	found, _ := e.A.scan(e.Cfg.Roots, e.Cfg, 120)
	check(t, len(found) == 1 && found[outer], "wrong scan %v", found)
}
func TestGlobDenyPathsApplyToDescendants(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/models"))
	f := e.make(t, "bucket", 30*day, map[string][]byte{"ok.bin": []byte("1")}, nil)
	check(t, e.A.evaluate(f, e.Cfg, e.Reg, true).Safe, "ordinary bucket denied")
	must(t, os.Mkdir(filepath.Join(f, "models"), 0755))
	must(t, os.WriteFile(filepath.Join(f, "models/w.bin"), []byte("w"), 0644))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "deny-listed"), "%s", debugVerdict(v))
	check(t, e.A.denyReason(filepath.Join(f, "models"), e.Cfg) != "", "denied directory allowed")
	h := e.make(t, "b2", 30*day, map[string][]byte{"inner/secret/x": []byte("1")}, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(h, "inner/secret"))
	check(t, !e.A.evaluate(h, e.Cfg, e.Reg, true).Safe, "exact descendant deny ignored")
}
func TestSessionGraceConfigParsing(t *testing.T) {
	e := newTestEnv(t)
	p := filepath.Join(e.Root, "c.toml")
	must(t, os.WriteFile(p, []byte("session_grace = \"72h\"\n"), 0644))
	cfg, err := e.A.loadConfig(p)
	must(t, err)
	check(t, cfg.SessionGrace != nil && *cfg.SessionGrace == 72*3600, "wrong grace")
	cfg, err = e.A.loadConfig(filepath.Join(e.Root, "none.toml"))
	must(t, err)
	check(t, cfg.SessionGrace == nil, "grace not unset")
	must(t, os.WriteFile(p, []byte("session_grace = \"soon\"\n"), 0644))
	_, err = e.A.loadConfig(p)
	check(t, err != nil, "invalid grace accepted")
}

func TestRelativePathChecksAbsoluteAncestors(t *testing.T) {
	e := newTestEnv(t)
	parent := filepath.Join(e.Root, "data/.git")
	must(t, os.MkdirAll(filepath.Join(parent, "cache"), 0755))
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(parent))
	defer os.Chdir(cwd)
	check(t, e.A.denyReason("cache", e.Cfg) == "inside a .git/.jj dir", "relative path bypassed repository metadata deny")
}
func TestGlobUnicodeAndWildcardParity(t *testing.T) {
	for _, c := range []struct {
		name, pat string
		want      bool
	}{{"café-data", "café*", true}, {"/a/x/y", "/a/*", true}, {".hidden", "*", true}, {"a", "[!b]", true}, {"]", "[]a]", true}, {"^", "[^a]", true}, {"-", "[-a]", true}, {"-", "[a-]", true}, {"x", "[!x]", false}, {"c", "[z-a-c]", true}, {"-", "[z-a-c]", true}, {"b", "[a--b]", true}, {"[x", "[x", true}, {"\xff.photoslibrary", "*.photoslibrary", true}} {
		t.Run(c.name+"_"+c.pat, func(t *testing.T) { check(t, globMatch(c.name, c.pat) == c.want, "glob mismatch %q %q", c.name, c.pat) })
	}
	e := newTestEnv(t)
	e.Cfg.DenyNames = append(e.Cfg.DenyNames, "café*")
	f := e.make(t, "unicode", 30*day, map[string][]byte{"café-cache/file": []byte("x")}, nil)
	check(t, !e.A.evaluate(f, e.Cfg, e.Reg, true).Safe, "Unicode descendant deny bypassed")
}
func TestMarkerNumbersRemainExact(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "precise", 0, nil, nil)
	must(t, os.WriteFile(filepath.Join(f, markerName), []byte(`{"owner":"test","regenerate":"rerun","job":9007199254740993,"custom":9007199254740993}`), 0600))
	m, err := e.A.readMarker(f)
	must(t, err)
	check(t, m.Job == "9007199254740993", "job rounded %q", m.Job)
	must(t, e.A.writeMarker(m))
	b, err := os.ReadFile(m.path())
	must(t, err)
	check(t, strings.Contains(string(b), `"custom": 9007199254740993`), "unknown integer rounded %s", b)
}
func TestSizesRejectOverflow(t *testing.T) {
	for _, s := range []string{"9223372036.854776GB", "999999999999999999999999999999999999999GB"} {
		_, err := parseSize(s)
		check(t, err != nil, "overflow accepted %s", s)
	}
	for _, v := range []any{"NaN", "Inf", 1e100, -1e100} {
		_, err := sizeKey(map[string]any{"floor_gb": v}, "floor", 0)
		check(t, err != nil, "bad size accepted %v", v)
	}
}

func TestRelativeMarkerStillChecksAbsoluteDescendantGlobs(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 30*day, map[string][]byte{"models/w.bin": []byte("precious")}, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/models"))
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(filepath.Dir(f)))
	defer os.Chdir(cwd)
	v := e.A.evaluate("bucket", e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "contains deny-listed models"), "relative descendant bypass: %s", debugVerdict(v))
}

func TestRelativeMarkersRespectAbsoluteLeaseAndClaimPaths(t *testing.T) {
	for _, kind := range []string{"lease", "claim", "cwd"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "bucket", 30*day, nil, nil)
			switch kind {
			case "lease":
				must(t, writeJSON(filepath.Join(e.Root, "leases/reader.json"), map[string]any{"pid": os.Getpid(), "what": f}))
			case "claim":
				must(t, writeJSON(filepath.Join(e.Root, "claims/reader.json"), map[string]any{"state": "starting", "cwd": f}))
			case "cwd":
				must(t, writeJSON(filepath.Join(e.Root, "leases/reader.json"), map[string]any{"pid": os.Getpid()}))
				e.A.ProcessCwd = func(int) string { return f }
			}
			cwd, err := os.Getwd()
			must(t, err)
			must(t, os.Chdir(filepath.Dir(f)))
			defer os.Chdir(cwd)
			v := e.A.evaluate("bucket", e.Cfg, e.Reg, true)
			check(t, !v.Safe && strings.Contains(v.Reason, "held:"), "relative %s bypass: %s", kind, debugVerdict(v))
		})
	}
}

func TestRelativeMarkAndEvaluateApplyAbsoluteGlobDeny(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 30*day, map[string][]byte{"models/w.bin": []byte("w")}, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/models"))
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(filepath.Dir(f)))
	defer os.Chdir(cwd)
	abs := e.A.evaluate(f, e.Cfg, e.Reg, true)
	rel := e.A.evaluate("bucket", e.Cfg, e.Reg, true)
	check(t, !abs.Safe && !rel.Safe && rel.Folder == f && strings.Contains(rel.Reason, "deny-listed"), "%+v", rel)
	for _, p := range []string{"other", "../data/./other2"} {
		check(t, e.A.main([]string{"mark", p, "-o", "t", "-r", "r"}) == 0, "relative mark failed")
		reg, err := e.A.loadRegistry()
		must(t, err)
		check(t, dict(mapEntry(reg, "markers")[e.A.expand(p)]) != nil, "absolute registration missing")
	}
}
func TestRelativeRegistryEntriesAreIgnoredNotDeleted(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 30*day, nil, nil)
	cwd, err := os.Getwd()
	must(t, err)
	must(t, os.Chdir(filepath.Dir(f)))
	defer os.Chdir(cwd)
	reg := map[string]any{"markers": map[string]any{"bucket": map[string]any{"registered": 1}, f + "/": map[string]any{"registered": 2}}}
	folders, err := e.A.discover(e.Cfg, reg, false, nil)
	must(t, err)
	check(t, len(folders) == 1 && folders[0] == f, "wrong folders %v", folders)
	markers := mapEntry(reg, "markers")
	check(t, dict(markers["bucket"]) != nil && dict(markers[f]) != nil && markers[f+"/"] == nil, "wrong registry %v", markers)
	log, err := os.ReadFile(e.A.LogFile)
	must(t, err)
	check(t, strings.Contains(string(log), "ignoring relative registry path") && exists(f), "relative registry acted on")
}

func TestMarkerWithoutRegenerateIsInvalidAndKept(t *testing.T) {
	for i, bad := range []any{"", "  ", 5, nil} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "noregen", 99*day, nil, map[string]any{"regenerate": bad})
			v := e.A.evaluate(f, e.Cfg, e.Reg, true)
			check(t, !v.Safe && strings.Contains(v.Reason, "regenerate"), "%s", debugVerdict(v))
			g := e.make(t, "noregen2", 99*day, nil, nil)
			must(t, writeJSON(filepath.Join(g, markerName), map[string]any{"owner": "test"}))
			check(t, strings.Contains(e.A.evaluate(g, e.Cfg, e.Reg, true).Reason, "regenerate"), "missing regenerate accepted")
		})
	}
}
func TestIgnoredOkMustBeBoolean(t *testing.T) {
	for i, bad := range []any{"true", 1, nil, []any{}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "badignored", 99*day, nil, map[string]any{"ignored_ok": bad})
			check(t, !e.A.evaluate(f, e.Cfg, e.Reg, true).Safe, "invalid ignored_ok accepted")
		})
	}
}
