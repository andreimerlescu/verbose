package verbose

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// sanitizeInput uses the secrets.max and secrets.min values as substring lengths to sanitize the input string
func sanitizeInput(input string) string {
	if len(input) == 0 {
		return input
	}
	var substrLengths []int                 // lengths to use for heuristics
	var mSubstrLen = make(map[int]struct{}) // collect unique lengths
	// set minimum secret length
	secrets.mmu.Lock()
	if secrets.min < 1 {
		secrets.min = SecretMinLength
	}
	secrets.mmu.Unlock()
	// lengths
	secrets.lmu.RLock() // lock lengths map
	for _, length := range secrets.Lengths {
		mSubstrLen[length] = struct{}{} // add/replace unique length to map
	}
	secrets.lmu.RUnlock() // unlock lengths map

	// can we proceed?
	if len(mSubstrLen) == 0 { // any lengths? if none, then
		return input
	}
	for i, _ := range mSubstrLen { // add unique lengths to substrLengths
		substrLengths = append(substrLengths, i)
	}
	slices.Reverse(substrLengths) // reverse them so the longest hashes are calculated first
	numWorkers := 8192
	type foundSecret struct {
		start, end  int
		replaceWith string
	}
	foundSecrets := make([]foundSecret, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	type dJob struct {
		start, end int
		substr     string
	}
	jobs := make(chan dJob, len(input)*len(substrLengths))
	hash := func() {
		defer wg.Done()
		for job := range jobs {
			hash := sha512.Sum512([]byte(job.substr))
			hashStr := hex.EncodeToString(hash[:])
			secrets.hmu.RLock()
			replaceWith, exists := secrets.Hashes[hashStr]
			secrets.hmu.RUnlock()
			if exists {
				mu.Lock()
				foundSecrets = append(foundSecrets, foundSecret{
					start:       job.start,
					end:         job.end,
					replaceWith: replaceWith,
				})
				mu.Unlock()
			}
		}
	}
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go hash()
	}
	for _, length := range substrLengths {
		for start := 0; start <= len(input)-length; start++ {
			jobs <- dJob{
				start:  start,
				end:    start + length,
				substr: input[start : start+length],
			}
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(foundSecrets, func(i, j int) bool {
		return foundSecrets[i].start < foundSecrets[j].start
	})
	sanitized, offset := input, 0
	for _, secret := range foundSecrets {
		sanitized = sanitized[:secret.start+offset] + // start + offset
			secret.replaceWith + // insert replaceWith value
			sanitized[secret.end+offset:] // end + offset
		// update offset to reflect replaceWith
		offset += len(secret.replaceWith) - (secret.end - secret.start)
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
