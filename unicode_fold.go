package main

import (
	"sort"
	"strings"
)

const (
	hangulSBase  rune = 44032
	hangulLBase  rune = 4352
	hangulVBase  rune = 4449
	hangulTBase  rune = 4519
	hangulLCount      = 19
	hangulVCount      = 21
	hangulTCount      = 28
	hangulNCount      = hangulVCount * hangulTCount
	hangulSCount      = hangulLCount * hangulNCount
)

// nfkc performs compatibility decomposition, canonical ordering, then canonical
// composition. Table decompositions are already recursive; Hangul is algorithmic.
func nfkc(text string) string {
	decomposed := make([]rune, 0, len(text))
	for _, r := range text {
		if r >= hangulSBase && r < hangulSBase+hangulSCount {
			index := r - hangulSBase
			decomposed = append(decomposed, hangulLBase+index/hangulNCount, hangulVBase+(index%hangulNCount)/hangulTCount)
			if trailing := index % hangulTCount; trailing != 0 {
				decomposed = append(decomposed, hangulTBase+trailing)
			}
		} else if expansion, ok := unicodeNFKD[r]; ok {
			decomposed = append(decomposed, expansion...)
		} else {
			decomposed = append(decomposed, r)
		}
	}
	// A class-zero character begins a segment. Stable ordering preserves marks
	// with equal combining classes, as required by the composition blocking rule.
	for start := 0; start < len(decomposed); {
		end := start + 1
		for end < len(decomposed) && unicodeCombiningClass[decomposed[end]] != 0 {
			end++
		}
		if end-start > 1 {
			segment := decomposed[start:end]
			sort.SliceStable(segment, func(i, j int) bool { return unicodeCombiningClass[segment[i]] < unicodeCombiningClass[segment[j]] })
		}
		start = end
	}
	if len(decomposed) == 0 {
		return ""
	}
	out := make([]rune, 0, len(decomposed))
	out = append(out, decomposed[0])
	starterIndex := 0
	starter := decomposed[0]
	lastClass := unicodeCombiningClass[starter]
	if lastClass != 0 {
		starterIndex = -1
	}
	for _, r := range decomposed[1:] {
		class := unicodeCombiningClass[r]
		if starterIndex >= 0 && (lastClass < class || lastClass == 0) {
			if joined, ok := composeUnicode(starter, r); ok {
				out[starterIndex] = joined
				starter = joined
				continue
			}
		}
		if class == 0 {
			starterIndex = len(out)
			starter = r
		}
		lastClass = class
		out = append(out, r)
	}
	return string(out)
}
func composeUnicode(first, second rune) (rune, bool) {
	if first >= hangulLBase && first < hangulLBase+hangulLCount && second >= hangulVBase && second < hangulVBase+hangulVCount {
		return hangulSBase + (first-hangulLBase)*hangulNCount + (second-hangulVBase)*hangulTCount, true
	}
	if first >= hangulSBase && first < hangulSBase+hangulSCount && (first-hangulSBase)%hangulTCount == 0 && second > hangulTBase && second < hangulTBase+hangulTCount {
		return first + second - hangulTBase, true
	}
	joined, ok := unicodeComposition[uint64(first)<<21|uint64(second)]
	return joined, ok
}

// fold matches NFKC(text).casefold() followed by NFKC using a pinned Unicode
// database. It deliberately retains composed characters for glob '?' semantics.
func fold(text string) string {
	ascii := true
	for i := 0; i < len(text); i++ {
		if text[i] >= 128 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(text)
	}
	normalized := nfkc(text)
	out := make([]rune, 0, len(normalized))
	for _, r := range normalized {
		if expansion, ok := unicodeCaseFold[r]; ok {
			out = append(out, expansion...)
		} else {
			out = append(out, r)
		}
	}
	return nfkc(string(out))
}
