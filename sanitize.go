package verbose

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// foundSecret records the location and replacement text of a detected secret
// within an input string.
type foundSecret struct {
	start, end  int
	replaceWith string
}

// sanitizeInput uses the secrets.max and secrets.min values as substring lengths to sanitize the input string
func sanitizeInput(input string) string {
	if len(input) == 0 {
		return input
	}

	// snapshot lengths under lock
	secrets.lmu.RLock()
	mSubstrLen := make(map[int]struct{}, len(secrets.Lengths))
	for _, length := range secrets.Lengths {
		mSubstrLen[length] = struct{}{}
	}
	secrets.lmu.RUnlock()

	if len(mSubstrLen) == 0 {
		return input
	}

	// short circuit if input can't possibly contain any registered secret
	secrets.mmu.Lock()
	if secrets.min < 1 {
		secrets.min = SecretMinLength
	}
	minLen := secrets.min
	secrets.mmu.Unlock()

	if len(input) < minLen {
		return input
	}

	substrLengths := make([]int, 0, len(mSubstrLen))
	for l := range mSubstrLen {
		substrLengths = append(substrLengths, l)
	}
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

func Sanitize(a ...interface{}) {
	in := fmt.Sprint(a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}

func Sanitizef(format string, a ...interface{}) {
	format = strings.Clone(sanitizeInput(format))
	in := fmt.Sprintf(format, a...)
	out := sanitizeInput(in)
	vLogr.Logger.Println(out)
}

// TODO foundSecret struct missing

// mergeOverlapping collapses any overlapping foundSecret ranges
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
