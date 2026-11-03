package main

import (
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
