// Copyright 2024 Google LLC
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

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

func TestParseHashAlgo(t *testing.T) {
	tests := []struct {
		input   string
		want    cpb.Tpm20HashAlgo
		wantErr bool
	}{
		{input: "SHA256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "sha256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "TPM_2_0_HASH_ALGO_SHA256", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256},
		{input: "SHA384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "sha384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "TPM_2_0_HASH_ALGO_SHA384", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "  sha384  ", want: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384},
		{input: "SHA512", wantErr: true},
		{input: "invalid", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseHashAlgo(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseHashAlgo(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseHashAlgo(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseExpectedPCRs(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMap     map[int][]byte
		wantIndices []int32
		wantErr     bool
	}{
		{
			name:  "valid",
			input: `{"0":"010203","4":"040506"}`,
			wantMap: map[int][]byte{
				0: {0x01, 0x02, 0x03},
				4: {0x04, 0x05, 0x06},
			},
			wantIndices: []int32{0, 4},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "empty json object",
			input:   "{}",
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   `not-json`,
			wantErr: true,
		},
		{
			name:    "non-numeric index",
			input:   `{"abc":"0102"}`,
			wantErr: true,
		},
		{
			name:    "invalid hex value",
			input:   `{"0":"not-hex"}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMap, gotIndices, err := parseExpectedPCRs(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseExpectedPCRs(%q) error = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr {
				if diff := cmp.Diff(tc.wantMap, gotMap); diff != "" {
					t.Errorf("parseExpectedPCRs(%q) map mismatch (-want +got):\n%s", tc.input, diff)
				}
				if diff := cmp.Diff(tc.wantIndices, gotIndices); diff != "" {
					t.Errorf("parseExpectedPCRs(%q) indices mismatch (-want +got):\n%s", tc.input, diff)
				}
			}
		})
	}
}
