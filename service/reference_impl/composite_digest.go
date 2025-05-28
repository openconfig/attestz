// Package reference_impl contains code snippets representing how the Attestz
// service does certain Attestation operations.
package reference_impl

import "crypto/sha256"

// PCR represents a PCR value received from a network device.
type PCR struct {
	// Index is the PCR's index. 0 - 23 are the possible indexes.
	Index uint8
	// Value is the unencoded raw bytes representing the PCR value.
	Value []byte
}

// Digest creates the allowed digest from sorted *returned* PCR's. (i.e
// the PCR values requested in Attestz/returned only)
func Digest(pcrs []PCR) []byte {
	h := sha256.New()
	for _, pcr := range pcrs {
		h.Write(pcr.Value)
	}
	return h.Sum(nil)
}
