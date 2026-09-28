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

package pcrprovider

import (
	"crypto"
	"strings"
	"testing"
)

func TestExpectedPCRs_Success(t *testing.T) {
	tests := []struct {
		name        string
		device      string
		hashAlgo    crypto.Hash
		wantIndices []int32
	}{
		{
			name:        "example-device using SHA-384",
			device:      "example-device",
			hashAlgo:    crypto.SHA384,
			wantIndices: []int32{0, 1, 2},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			provider := NewTestPCRProvider()

			pcrs, err := provider.ExpectedPCRs(ctx, tc.device)
			if err != nil {
				t.Fatalf("ExpectedPCRs(ctx, %q) returned unexpected error: %v", tc.device, err)
			}

			if len(pcrs) != len(tc.wantIndices) {
				t.Errorf("ExpectedPCRs returned %d PCRs, want %d", len(pcrs), len(tc.wantIndices))
			}

			wantLen := tc.hashAlgo.Size()
			for _, idx := range tc.wantIndices {
				digests, ok := pcrs[idx]
				if !ok || len(digests) == 0 {
					t.Errorf("ExpectedPCRs missing PCR index %d", idx)
					continue
				}
				for _, digest := range digests {
					if len(digest) != wantLen {
						t.Errorf("PCR index %d has digest length %d, want %d (%s)", idx, len(digest), wantLen, tc.hashAlgo)
					}
				}
			}
		})
	}
}

func TestExpectedPCRs_Failure(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		wantSubstr string
	}{
		{
			name:       "unknown device",
			device:     "unknown-device",
			wantSubstr: `no golden PCRs configured for device "unknown-device"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			provider := NewTestPCRProvider()

			_, err := provider.ExpectedPCRs(ctx, tc.device)
			if err == nil {
				t.Fatalf("ExpectedPCRs(ctx, %q) returned nil error, want error", tc.device)
			}

			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("ExpectedPCRs(ctx, %q) error = %q, want substring %q", tc.device, err.Error(), tc.wantSubstr)
			}
		})
	}
}
