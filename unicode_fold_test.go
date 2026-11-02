package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os/exec"
	"sort"
	"testing"
	"unicode/utf8"
)

func TestUnicodeFoldRepresentativeForms(t *testing.T) {
	cases := map[string]string{
		"": "", "plain ASCII": "plain ascii", "Straße": "strasse", "ＥＸＡＭＰＬＥ": "example",
		"Å": "å", "café": "café", "cafe\u0301": "café", "İ": "i\u0307", "ﬃ": "ffi",
		"Σςσ": "σσσ", "①": "1", "\u1100\u1161\u11a8": "각", "\u0345": "ι",
		"A\u0315\u0300": "à\u0315", "\u0301A": "\u0301a", "\u2126": "ω",
	}
	for input, want := range cases {
		if got := fold(input); got != want {
			t.Errorf("fold(%q)=%q, want %q", input, got, want)
		}
	}
	// Decomposed equivalents must remain one composed character for glob '?'.
	if got := fold("e\u0301"); utf8.RuneCountInString(got) != 1 || got != "é" {
		t.Fatalf("fold did not recompose: %q", got)
	}
}

func TestUnicodeFoldPythonDifferential(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python is needed only for differential tests")
	}
	scalarSet := map[rune]bool{}
	for r := range unicodeNFKD {
		scalarSet[r] = true
	}
	for r := range unicodeCombiningClass {
		scalarSet[r] = true
	}
	for r := range unicodeCaseFold {
		scalarSet[r] = true
	}
	for key, r := range unicodeComposition {
		scalarSet[r] = true
		scalarSet[rune(key>>21)] = true
		scalarSet[rune(key&((1<<21)-1))] = true
	}
	for r := hangulSBase; r < hangulSBase+hangulSCount; r++ {
		scalarSet[r] = true
	}
	scalars := make([]rune, 0, len(scalarSet))
	for r := range scalarSet {
		scalars = append(scalars, r)
	}
	sort.Slice(scalars, func(i, j int) bool { return scalars[i] < scalars[j] })
	inputs := []string{"", "café", "cafe\u0301", "\u1100\u1161\u11a8", "\u0301\u0315A\u0315\u0300", "\u0301\u0323", "ßKﬃΣςİ"}
	for _, r := range scalars {
		inputs = append(inputs, string(r))
	}
	keys := make([]uint64, 0, len(unicodeComposition))
	for key := range unicodeComposition {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		first, second := rune(key>>21), rune(key&((1<<21)-1))
		inputs = append(inputs, string([]rune{first, second}), string([]rune{first, 769, second}), string([]rune{first, 789, second}))
	}
	random := rand.New(rand.NewSource(48391))
	marks := []rune{768, 769, 770, 775, 776, 789, 803, 807, 837, 847, 1160, 1161}
	for n := 0; n < 6000; n++ {
		length := random.Intn(12)
		sequence := make([]rune, 0, length)
		for i := 0; i < length; i++ {
			switch random.Intn(4) {
			case 0:
				sequence = append(sequence, marks[random.Intn(len(marks))])
			case 1:
				sequence = append(sequence, rune(random.Intn(128)))
			default:
				sequence = append(sequence, scalars[random.Intn(len(scalars))])
			}
		}
		inputs = append(inputs, string(sequence))
	}
	payload, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `import json,sys,unicodedata as u
inputs=json.load(sys.stdin)
print(json.dumps({"version":u.unidata_version,"values":[u.normalize("NFKC",u.normalize("NFKC",s).casefold()) for s in inputs]}))`)
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version string   `json:"version"`
		Values  []string `json:"values"`
	}
	if err = json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != unicodeDataVersion {
		t.Skipf("Python Unicode %s differs from pinned Unicode %s", result.Version, unicodeDataVersion)
	}
	if len(result.Values) != len(inputs) {
		t.Fatalf("Python returned %d values for %d cases", len(result.Values), len(inputs))
	}
	for i, input := range inputs {
		if got := fold(input); got != result.Values[i] {
			t.Fatalf("case %d: fold(%s)=%s, Python=%s", i, fmt.Sprintf("%q", input), fmt.Sprintf("%q", got), fmt.Sprintf("%q", result.Values[i]))
		}
	}
	t.Logf("matched Python Unicode %s over %d scalar, composition and random cases", result.Version, len(inputs))
}
