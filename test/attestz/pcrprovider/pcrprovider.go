//
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Package pcrprovider provides expected Platform Configuration Register (PCR) measurements.
package pcrprovider

import (
	"context"
	"encoding/hex"
	"fmt"
)

// TestPCRProvider is a minimal reference implementation skeleton that supplies expected
// Platform Configuration Register (PCR) values to the Attestz SUT controller.
// Implementers should replace or extend this with their concrete golden PCR lookup logic
// (e.g., querying an internal measurement database, manifest file, or RIM service).
type TestPCRProvider struct{}

// NewTestPCRProvider is a placeholder constructor for TestPCRProvider.
// Implementers should replace this with their concrete PCR provider constructor.
func NewTestPCRProvider() *TestPCRProvider {
	return &TestPCRProvider{}
}

// ExpectedPCRs returns the expected PCR index-to-digests mapping for a target device.
//
// Implementation Guidance:
//  1. Input: `device` is the management IP address or hostname of the target switch under test.
//  2. Retrieve the authoritative ("golden") PCR digests expected for the device's hardware and
//     boot software state.
//  3. Output: Return a map[int32][][]byte where each key is a TPM 2.0 PCR index (0-23) to be
//     queried and verified, and each value is a slice of acceptable raw binary digests expected
//     for that PCR (allowing multiple valid baselines per PCR index if needed).
//
// Note: The implementation below is provided only as a reference example. Implementers may
// modify this function or add methods to TestPCRProvider as needed to match how their
// environment stores and retrieves golden measurements.
func (p *TestPCRProvider) ExpectedPCRs(ctx context.Context, device string) (map[int32][][]byte, error) {
	var goldenPCRs map[int32][]string
	switch device {
	case "example-device":
		// Example hex-encoded SHA-384 golden PCR digests for a reference switch.
		// Replace "example-device" and these digests with your switch's management IP/hostname
		// and expected PCR measurements, or replace this switch block with a custom lookup.
		goldenPCRs = map[int32][]string{
			0: {"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"},
			1: {"1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"},
			2: {"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50"},
			// Add more PCRs as needed.
		}
	default:
		return nil, fmt.Errorf("no golden PCRs configured for device %q: please populate goldenPCRs or implement custom ExpectedPCRs lookup logic in pcrprovider.go", device)
	}

	res := make(map[int32][][]byte, len(goldenPCRs))
	for idx, hexDigests := range goldenPCRs {
		for _, hexDigest := range hexDigests {
			b, err := hex.DecodeString(hexDigest)
			if err != nil {
				return nil, fmt.Errorf("failed to decode golden PCR hex for device %q at PCR[%d]: %w", device, idx, err)
			}
			res[idx] = append(res[idx], b)
		}
	}
	return res, nil
}
