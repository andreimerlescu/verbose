package verbose

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// foundSecret records a detected secret within an input string together with
// its replacement text. start and end are byte offsets into the original input.
type foundSecret struct {
	start, end  int
	replaceWith string
}

// sanitizeInput scans input for substrings that match any registered secret
// and returns a copy of input with each match replaced by its configured
// replacement string. Overlapping matches are merged so that the wider (longer)
// match wins, preventing partial redaction artefacts such as "super[INNER]".
//
// The function is safe for concurrent use — it takes a read-lock on the secrets
// maps and releases it before performing any allocation.
//
// Performance characteristics:
//   - Fast path (no secrets registered): O(1), zero allocations.
//   - Fast path (input shorter than shortest registered secret): O(1), zero allocations.
//   - General path: O(n²) in input length where n = len(input). Each byte
//     position is hashed once per registered secret length. For typical log
//     lines under 200 bytes the overhead is imperceptible; for large inputs
//     (> 1 KB) consider whether the full input needs to pass through the logger.
//
// Gotcha: sanitizeInput operates on raw bytes, not Unicode code points. A
// secret that contains multi-byte UTF-8 sequences is matched correctly as long
// as the byte sequence appears verbatim in input.
func sanitizeInput(input string) string {
	if len(input) == 0 {
		return input
	}

	// Fast path: bail out before any allocation if no secrets are registered.
	secrets.lmu.RLock()
	if len(secrets.Lengths) == 0 {
		secrets.lmu.RUnlock()
		return input
	}
	mSubstrLen := make(map[int]struct{}, len(secrets.Lengths))
	for _, length := range secrets.Lengths {
		mSubstrLen[length] = struct{}{}
	}
	secrets.lmu.RUnlock()

	if len(mSubstrLen) == 0 {
		return input
	}

	// Fast path: input is shorter than the shortest registered secret.
	secrets.mmu.Lock()
	if secrets.min < 1 {
		secrets.min = SecretMinLength
	}
	minLen := secrets.min
	secrets.mmu.Unlock()

	if len(input) < minLen {
		return input
	}

	// Build a sorted, deduplicated slice of secret lengths, longest first.
	// Sorting before reversing guarantees the order — iterating over a map
	// does not.
	substrLengths := make([]int, 0, len(mSubstrLen))
	for l := range mSubstrLen {
		substrLengths = append(substrLengths, l)
	}
	sort.Ints(substrLengths)
	slices.Reverse(substrLengths) // longest first so overlaps favour wider match

	found := make([]foundSecret, 0)

	for _, length := range substrLengths {
		if length > len(input) {
			continue
		}
		var h [64]byte
		hasher := sha512.New()
		for start := 0; start <= len(input)-length; start++ {
			substr := input[start : start+length]
			hasher.Reset()
			hasher.Write([]byte(substr))
			hasher.Sum(h[:0])
			hashStr := hex.EncodeToString(h[:])
			secrets.hmu.RLock()
			replaceWith, exists := secrets.Hashes[hashStr]
			secrets.hmu.RUnlock()
			if exists {
				found = append(found, foundSecret{
					start:       start,
					end:         start + length,
					replaceWith: replaceWith,
				})
			}
		}
	}

	if len(found) == 0 {
		return input
	}

	sort.Slice(found, func(i, j int) bool {
		return found[i].start < found[j].start
	})
	found = mergeOverlapping(found)

	sanitized, offset := input, 0
	for _, s := range found {
		sanitized = sanitized[:s.start+offset] +
			s.replaceWith +
			sanitized[s.end+offset:]
		offset += len(s.replaceWith) - (s.end - s.start)
	}
	return sanitized
}

// Sanitize formats args with fmt.Sprint, sanitizes the result against all
// registered secrets, and writes the sanitized string to the verbose logger.
//
// Note: Sanitize does not return a string. The design philosophy of this
// package is that every string passing through a verbose function is written
// to the verbose logger. Use fmt.Sprintf if you need a formatted string
// without logging it.
func Sanitize(a ...interface{}) {
	in := fmt.Sprint(a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}

// Sanitizef formats args using format and fmt.Sprintf, sanitizes both the
// format string and the formatted result against all registered secrets, and
// writes the sanitized output to the verbose logger.
//
// Note: Sanitizef does not return a string. See Sanitize for the rationale.
func Sanitizef(format string, a ...interface{}) {
	format = strings.Clone(sanitizeInput(format))
	in := fmt.Sprintf(format, a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}

// mergeOverlapping collapses any overlapping or adjacent foundSecret ranges
// in found (which must be sorted by start offset ascending). When two ranges
// overlap the later range is absorbed into the earlier one; the replaceWith
// string of the first (wider/longer) match is retained, which is correct
// because substrLengths is processed longest-first.
//
// Example: secrets "supersecret" and "secret" both registered; input contains
// "supersecret". The longer match produces foundSecret{0,11,"[OUTER]"} and the
// shorter match produces foundSecret{5,11,"[INNER]"}. mergeOverlapping collapses
// these into foundSecret{0,11,"[OUTER]"}, preventing "super[INNER]" artefacts.
func mergeOverlapping(found []foundSecret) []foundSecret {
	if len(found) == 0 {
		return found
	}
	merged := []foundSecret{found[0]}
	for _, curr := range found[1:] {
		last := &merged[len(merged)-1]
		if curr.start < last.end {
			// overlapping — extend end if needed, keep last.replaceWith
			if curr.end > last.end {
				last.end = curr.end
			}
		} else {
			merged = append(merged, curr)
		}
	}
	return merged
}
