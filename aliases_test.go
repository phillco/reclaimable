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
