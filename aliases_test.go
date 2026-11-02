package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataVolumeAliasOfProtectedPathIsRefused(t *testing.T) {
	if !isDir(dataVolume) {
		t.Skip("no APFS Data volume here")
	}
	e := newTestEnv(t)
	protected := filepath.Join(e.Root, "data/protected")
	must(t, os.MkdirAll(protected, 0755))
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, protected)
	for _, p := range []string{filepath.Join(protected, "x"), dataVolume + protected, dataVolume + filepath.Join(protected, "x"), dataVolume + filepath.Join(e.A.Home, ".ssh/keys"), dataVolume + e.A.Home, dataVolume} {
		check(t, e.A.denyReason(p, e.Cfg) != "", "alias allowed %s", p)
	}
	check(t, e.A.main([]string{"mark", dataVolume + filepath.Join(protected, "x"), "-o", "t", "-r", "r"}) == 2, "alias mark allowed")
	f := e.make(t, "al", 30*day, nil, nil)
	check(t, e.A.evaluate(dataVolume+f, e.Cfg, e.Reg, true).Folder == f, "alias evaluation not canonical")
}
func TestCaseVariantsOfProtectedPaths(t *testing.T) {
	e := newTestEnv(t)
	must(t, os.Mkdir(filepath.Join(e.Root, "Documents"), 0755))
	must(t, os.Mkdir(filepath.Join(e.Root, "Protected"), 0755))
	e.Cfg.DenyExact = append(e.Cfg.DenyExact, filepath.Join(e.Root, "Documents"))
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "Protected"))
	for _, p := range []string{"documents", "DOCUMENTS", "protected/sub", "PROTECTED/sub"} {
		check(t, e.A.denyReason(filepath.Join(e.Root, p), e.Cfg) != "", "case variant allowed %s", p)
	}
	check(t, e.A.denyReason(filepath.Join(e.Root, "other"), e.Cfg) == "", "ordinary path denied")
}
func TestUnicodeNormalisationVariants(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.DenyNames = append(e.Cfg.DenyNames, "café")
	nfd := "café"
	check(t, e.A.denyReason(filepath.Join(e.Root, nfd), e.Cfg) != "", "NFD name bypassed deny")
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "café-keep"))
	check(t, e.A.denyReason(filepath.Join(e.Root, "café-keep/x"), e.Cfg) != "", "NFD path bypassed deny")
	f := e.make(t, "uni", 30*day, map[string][]byte{nfd + "/x": []byte("1")}, nil)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "deny-listed"), "%s", debugVerdict(v))
}
func TestPhotoslibraryUppercase(t *testing.T) {
	e := newTestEnv(t)
	for _, p := range []string{"Pics.PHOTOSLIBRARY/x", "Pics.PhotosLibrary"} {
		check(t, e.A.denyReason(filepath.Join(e.Root, p), e.Cfg) != "", "photo library case bypass %s", p)
	}
}
func TestCaseVariantDescendantNamesBlock(t *testing.T) {
	for _, rel := range []string{"x/Models/w.bin", "x/MODELS/w.bin", "Frozen-X/a", "a/Receipt", "Experiments/Results/r1"} {
		t.Run(rel, func(t *testing.T) {
			e := newTestEnv(t)
			e.Cfg.DenyNames = append(e.Cfg.DenyNames, "models", "frozen*", "*receipt*")
			e.Cfg.DenySequences = append(e.Cfg.DenySequences, []string{"experiments", "results"})
			f := e.make(t, "cv", 30*day, map[string][]byte{rel: []byte("1")}, nil)
			v := e.A.evaluate(f, e.Cfg, e.Reg, true)
			check(t, !v.Safe && strings.Contains(v.Reason, "deny-listed"), "%s", debugVerdict(v))
		})
	}
}
func TestCaseVariantDescendantGlobAndGitDirs(t *testing.T) {
	e := newTestEnv(t)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/Models"))
	f := e.make(t, "bk", 30*day, map[string][]byte{"models/w": []byte("1")}, nil)
	check(t, !e.A.evaluate(f, e.Cfg, e.Reg, true).Safe, "case variant descendant allowed")
	for _, p := range []string{"src/foo/.GIT", "src/foo/.Jj/repo"} {
		check(t, e.A.denyReason(filepath.Join(e.Root, p), e.Cfg) != "", "metadata case bypass %s", p)
	}
}
func TestIdentityCatchesOtherSpellingsOfAProtectedDir(t *testing.T) {
	e := newTestEnv(t)
	protected := filepath.Join(e.Root, "Keep")
	must(t, os.Mkdir(protected, 0755))
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, protected)
	other := filepath.Join(e.Root, "keep")
	if !exists(other) {
		t.Skip("case-sensitive filesystem")
	}
	one, ok := identity(other)
	check(t, ok, "missing alias identity")
	two, ok := identity(protected)
	check(t, ok && one == two, "different identity")
	check(t, e.A.denyReason(other, e.Cfg) != "" && len(e.A.protectedIdentities(e.Cfg)) > 0, "identity alias bypass")
}
func TestStripDataVolumeIsLexical(t *testing.T) {
	check(t, stripData(dataVolume) == "/", "volume root not canonical")
	check(t, stripData(dataVolume+"/tmp/cache") == "/tmp/cache", "volume prefix not stripped")
	check(t, stripData(dataVolume+"Extra/cache") == dataVolume+"Extra/cache", "unrelated prefix stripped")
}

func TestDataPrefixVariantsBlockCombinedGlobBypass(t *testing.T) {
	for _, prefix := range []string{"/system/volumes/data", "/sYsTeM/vOlUmEs/dAtA", "/ſystem/Volumes/Data", "/Ｓystem/Volumes/Data"} {
		t.Run(prefix, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "bucket", 30*day, map[string][]byte{"models/weights": []byte("keep")}, nil)
			e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/models"))
			v := e.A.evaluate(prefix+f, e.Cfg, e.Reg, true)
			check(t, v.Folder == f && !v.Safe && strings.Contains(v.Reason, "deny-list"), "%s", debugVerdict(v))
			b, err := os.ReadFile(filepath.Join(f, "models/weights"))
			must(t, err)
			check(t, string(b) == "keep", "payload changed")
		})
	}
}
func TestDecomposedDataPrefixIsCanonical(t *testing.T) {
	prior := dataVolume
	dataVolume = "/Systém/Volumes/Data"
	t.Cleanup(func() { dataVolume = prior })
	e := newTestEnv(t)
	f := e.make(t, "café", 0, map[string][]byte{"models/weights": []byte("keep")}, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "data/*/models"))
	v := e.A.evaluate("/sYSTÉM/vOLUMES/dATA"+f, e.Cfg, e.Reg, true)
	check(t, v.Folder == f && !v.Safe && strings.Contains(v.Reason, "deny-list"), "%s", debugVerdict(v))
}
func TestGlobDenyProtectsHardlinkIdentity(t *testing.T) {
	for _, pattern := range []string{"*.bin", "[w]*.bin", "?.bin"} {
		t.Run(pattern, func(t *testing.T) {
			e := newTestEnv(t)
			protected := filepath.Join(e.Root, "protected")
			must(t, os.Mkdir(protected, 0755))
			target := filepath.Join(protected, "w.bin")
			must(t, os.WriteFile(target, []byte("keep"), 0644))
			f := e.make(t, "bucket", 0, nil, nil)
			must(t, os.Link(target, filepath.Join(f, "innocent")))
			e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(protected, pattern))
			id, ok := identity(target)
			check(t, ok && e.A.protectedIdentities(e.Cfg)[id], "glob omitted protected identity")
			v := e.A.evaluate(f, e.Cfg, e.Reg, true)
			check(t, !v.Safe && strings.Contains(v.Reason, "deny-list"), "%s", debugVerdict(v))
		})
	}
}
func TestGlobIdentityExpansionFoldsLiteralComponents(t *testing.T) {
	e := newTestEnv(t)
	protected := filepath.Join(e.Root, "café-keep")
	must(t, os.Mkdir(protected, 0755))
	target := filepath.Join(protected, "Weights.bin")
	must(t, os.WriteFile(target, []byte("keep"), 0644))
	f := e.make(t, "bucket", 0, nil, nil)
	must(t, os.Link(target, filepath.Join(f, "innocent")))
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "CAFÉ-KEEP/*.BIN"))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe, "%s", debugVerdict(v))
}
func TestUnreadableDenyGlobFailsClosed(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 0, nil, nil)
	protected := filepath.Join(e.Root, "protected")
	must(t, os.Mkdir(protected, 0755))
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(protected, "*/models"))
	real := e.A.ListDir
	e.A.ListDir = func(path string) ([]os.DirEntry, error) {
		if path == protected {
			return nil, os.ErrPermission
		}
		return real(path)
	}
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "unreadable") && e.A.denyReason(f, e.Cfg) != "", "%s", debugVerdict(v))
}
func TestDataPrefixVariantsInDenyPatternsAndWalk(t *testing.T) {
	for _, prefix := range []string{"/system/volumes/data", "/sYsTeM/vOlUmEs/dAtA"} {
		t.Run(prefix, func(t *testing.T) {
			e := newTestEnv(t)
			f := e.make(t, "bucket", 0, map[string][]byte{"models/weights": []byte("keep")}, nil)
			e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, prefix+filepath.Join(e.Root, "data/*/models"))
			w := e.A.walk(f, e.Cfg, true, 300)
			check(t, w.Problem != "", "walk permitted aliased deny")
			check(t, e.A.denyReason(prefix+filepath.Join(f, "models"), e.Cfg) != "", "aliased path allowed")
			check(t, e.A.denyReason(prefix+"/Users", e.Cfg) != "", "broad alias allowed")
		})
	}
}
func TestRelatedPathsFoldNormaliseAndStripPrefix(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "café", 0, nil, nil)
	ref := "/system/volumes/data" + strings.ToUpper(strings.ReplaceAll(f, "é", "é"))
	check(t, related(filepath.Join(ref, "child"), f) && related(f, filepath.Join(ref, "child")), "related aliases missed")
	check(t, !related(f, f+"-other"), "component boundary ignored")
}
func TestLeaseDataAliasAndCaseVariantHolds(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "café", 0, nil, nil)
	must(t, writeJSON(filepath.Join(e.Root, "leases/1.json"), map[string]any{"pid": os.Getpid(), "what": "/system/volumes/data" + strings.ToUpper(f)}))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "lease"), "%s", debugVerdict(v))
}
func TestDiscoveryRootsUseCanonicalComparisons(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "café", 0, nil, nil)
	reg := map[string]any{"markers": map[string]any{f: map[string]any{}}, "last_scan": e.A.Now()}
	root := "/system/volumes/data" + strings.ToUpper(filepath.Dir(f))
	found, err := e.A.discover(e.Cfg, reg, false, []string{root})
	must(t, err)
	check(t, len(found) == 1 && found[0] == f, "found %v", found)
}
func TestExportBroadRootsUseCanonicalComparisons(t *testing.T) {
	e := newTestEnv(t)
	e.A.Home = filepath.Join(e.Root, "Home")
	check(t, !e.A.exportOK("/system/volumes/data"+strings.ToUpper(e.A.Home)), "home alias export allowed")
	check(t, !e.A.exportOK(filepath.Join("/system/volumes/data/uSeRs", "example")), "broad root alias export allowed")
}
func TestDoubleSlashDataPrefixAndComponentBoundaries(t *testing.T) {
	e := newTestEnv(t)
	check(t, e.A.expand("//sYsTeM/Volumes/Data/Users") == "/Users", "double slash data alias not canonical")
	check(t, e.A.denyReason("//Users", e.Cfg) != "", "double slash broad root allowed")
	check(t, e.A.expand("/System/Volumes/Database/x") == "/System/Volumes/Database/x", "component boundary lost")
}
func TestScanPruningFoldsPathsAndNames(t *testing.T) {
	e := newTestEnv(t)
	e.make(t, "NODE_MODULES/cache", 0, nil, nil)
	e.make(t, "ordinary/.GIT/cache", 0, nil, nil)
	f := e.make(t, "café/cache", 0, nil, nil)
	prior := prunePaths
	prunePaths = []string{strings.ToUpper(filepath.Dir(f))}
	t.Cleanup(func() { prunePaths = prior })
	found, complete := e.A.scan(e.Cfg.Roots, e.Cfg, 120)
	check(t, complete && len(found) == 0, "found %v complete=%v", found, complete)
}
func TestHoldPathsDeduplicateAndReleaseCanonicalAlias(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "café", 0, nil, nil)
	child := filepath.Join(f, "part")
	other := "/sYsTeM/Volumes/Data" + strings.ToUpper(strings.ReplaceAll(child, "é", "é"))
	check(t, e.A.main([]string{"hold", f, "job42", "-p", child}) == 0, "initial hold failed")
	check(t, e.A.main([]string{"hold", f, "job42", "-p", other}) == 0, "alias hold failed")
	m, err := e.A.readMarker(f)
	must(t, err)
	check(t, len(m.Holds) == 1, "alias hold duplicated %v", m.Holds)
	check(t, e.A.main([]string{"release", f, "job42", "-p", child}) == 0, "canonical release failed")
	m, err = e.A.readMarker(f)
	must(t, err)
	check(t, len(m.Holds) == 0, "hold remained %v", m.Holds)
}
func TestVolumeFloorLookupUsesCanonicalPath(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 0, nil, nil)
	mount := filepath.Dir(f)
	e.A.IsMount = func(p string) bool { return p == mount }
	e.Cfg.VolumeFloors = map[string]int64{"/system/volumes/data" + strings.ToUpper(mount): 123}
	floor, _, ok := e.A.volumeLimits(f, e.Cfg)
	check(t, ok && floor == 123, "floor %d configured=%v", floor, ok)
}
func TestGlobAncestorIdentityProtectsOtherAlias(t *testing.T) {
	e := newTestEnv(t)
	protected := filepath.Join(e.Root, "keep")
	must(t, os.MkdirAll(filepath.Join(protected, "child"), 0755))
	f := e.make(t, "bucket", 0, nil, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(protected, "chi?d"))
	real := e.A.Identity
	e.A.Identity = func(path string) (FileIdentity, bool) {
		if path == f {
			return real(protected)
		}
		return real(path)
	}
	check(t, e.A.denyReason(f, e.Cfg) != "", "ancestor identity alias allowed")
}
func TestMissingGlobIsNotAGlobalVeto(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "bucket", 0, nil, nil)
	e.Cfg.DenyPaths = append(e.Cfg.DenyPaths, filepath.Join(e.Root, "absent/*/models"))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe, "%s", debugVerdict(v))
}
