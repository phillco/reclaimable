package main

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// fold retains composed characters so glob '?' matches a normalized character.
func fold(text string) string {
	return norm.NFKC.String(cases.Fold().String(norm.NFKC.String(text)))
}
