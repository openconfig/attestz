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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCertPath(t *testing.T) {
	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "secret_cert.crt")
	if err := os.WriteFile(existingFile, []byte("CERT_DATA"), 0644); err != nil {
		t.Fatalf("Failed to create temporary cert file: %v", err)
	}

	nonExistentFile := filepath.Join(tempDir, "missing_cert.crt")
	defaultFallback := "/app/certs/ownerca.crt"

	tests := []struct {
		name            string
		secretMountPath string
		fallback        string
		wantResult      string
	}{
		{
			name:            "Mounted secret certificate exists",
			secretMountPath: existingFile,
			fallback:        defaultFallback,
			wantResult:      existingFile,
		},
		{
			name:            "Mounted secret certificate does not exist, falls back",
			secretMountPath: nonExistentFile,
			fallback:        defaultFallback,
			wantResult:      defaultFallback,
		},
		{
			name:            "Empty secret mount path, falls back",
			secretMountPath: "",
			fallback:        defaultFallback,
			wantResult:      defaultFallback,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveCertPath(tc.secretMountPath, tc.fallback)
			if got != tc.wantResult {
				t.Errorf("resolveCertPath(%q, %q) = %q, want %q", tc.secretMountPath, tc.fallback, got, tc.wantResult)
			}
		})
	}
}
