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
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
)

// mockPKIProvider implements caservice.PKIProvider for unit testing.
type mockPKIProvider struct {
	deviceTrustBundleFn         func() *x509.CertPool
	issueOIAKFn                 func(iakPem string) (string, error)
	issueOIDevIDFn              func(idevidPem string) (string, error)
	generateClientCredentialsFn func() ([]byte, []byte, error)
}

func (m *mockPKIProvider) DeviceTrustBundle() *x509.CertPool {
	if m.deviceTrustBundleFn != nil {
		return m.deviceTrustBundleFn()
	}
	return nil
}

func (m *mockPKIProvider) IssueOIAK(iakPem string) (string, error) {
	if m.issueOIAKFn != nil {
		return m.issueOIAKFn(iakPem)
	}
	return "MINTED_OIAK_PEM", nil
}

func (m *mockPKIProvider) IssueOIDevID(idevidPem string) (string, error) {
	if m.issueOIDevIDFn != nil {
		return m.issueOIDevIDFn(idevidPem)
	}
	return "MINTED_OIDEVID_PEM", nil
}

func (m *mockPKIProvider) GenerateClientCredentials() ([]byte, []byte, error) {
	if m.generateClientCredentialsFn != nil {
		return m.generateClientCredentialsFn()
	}
	return nil, nil, nil
}

func TestGetSerialNumber(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Standard format with space",
			input: "SN: 12345678",
			want:  "12345678",
		},
		{
			name:  "Standard format without space",
			input: "SN:ABCD-9999",
			want:  "ABCD-9999",
		},
		{
			name:  "Plain serial without SN prefix",
			input: "SERIAL12345",
			want:  "SERIAL12345",
		},
		{
			name:  "Surrounding whitespace",
			input: "   SN:   XYZ-001   ",
			want:  "XYZ-001",
		},
		{
			name:  "Empty string",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getSerialNumber(tc.input)
			if got != tc.want {
				t.Errorf("getSerialNumber(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateCerts(t *testing.T) {
	fakePool := x509.NewCertPool()
	trustedPool := x509.NewCertPool()
	trustedPool.AppendCertsFromPEM([]byte(validTestCertPEMWithSN))
	trustedPool.AppendCertsFromPEM([]byte(testCertPEMWithDiffSN))
	trustedPool.AppendCertsFromPEM([]byte(certPEMWithoutSN))
	s := &Service{}

	tests := []struct {
		name              string
		idevid            string
		iak               string
		deviceTrustBundle *x509.CertPool
		wantErrSub        string
	}{
		{
			name:              "Missing idevid cert",
			idevid:            "",
			iak:               dummyPEM,
			deviceTrustBundle: fakePool,
			wantErrSub:        "missing certificate or trust bundle",
		},
		{
			name:              "Missing iak cert",
			idevid:            dummyPEM,
			iak:               "",
			deviceTrustBundle: fakePool,
			wantErrSub:        "missing certificate or trust bundle",
		},
		{
			name:              "Nil trust bundle",
			idevid:            dummyPEM,
			iak:               dummyPEM,
			deviceTrustBundle: nil,
			wantErrSub:        "missing certificate or trust bundle",
		},
		{
			name:              "Malformed idevid PEM",
			idevid:            "NOT-A-PEM-STRING",
			iak:               dummyPEM,
			deviceTrustBundle: fakePool,
			wantErrSub:        "failed to decode IDevID PEM",
		},
		{
			name:              "Malformed iak PEM",
			idevid:            validTestCertPEMWithSN,
			iak:               "NOT-A-PEM-STRING",
			deviceTrustBundle: fakePool,
			wantErrSub:        "failed to decode IAK PEM",
		},
		{
			name:              "Invalid cert DER bytes in IDevID",
			idevid:            invalidDERPEM,
			iak:               validTestCertPEMWithSN,
			deviceTrustBundle: fakePool,
			wantErrSub:        "failed to parse IDevID cert",
		},
		{
			name:              "Invalid cert DER bytes in IAK",
			idevid:            validTestCertPEMWithSN,
			iak:               invalidDERPEM,
			deviceTrustBundle: fakePool,
			wantErrSub:        "failed to parse IAK cert",
		},
		{
			name:              "Untrusted IDevID cert",
			idevid:            validTestCertPEMWithSN,
			iak:               validTestCertPEMWithSN,
			deviceTrustBundle: fakePool,
			wantErrSub:        "failed to verify IDevID",
		},
		{
			name:              "Empty serial number in certificates",
			idevid:            certPEMWithoutSN,
			iak:               certPEMWithoutSN,
			deviceTrustBundle: trustedPool,
			wantErrSub:        "certificate missing subject serial number",
		},
		{
			name:              "Serial number mismatch",
			idevid:            validTestCertPEMWithSN,
			iak:               testCertPEMWithDiffSN,
			deviceTrustBundle: trustedPool,
			wantErrSub:        "serial number mismatch",
		},
		{
			name:              "Valid certificates with matching serial numbers",
			idevid:            validTestCertPEMWithSN,
			iak:               validTestCertPEMWithSN,
			deviceTrustBundle: trustedPool,
			wantErrSub:        "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.validateCerts(tc.idevid, tc.iak, tc.deviceTrustBundle)
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("validateCerts() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateCerts() expected error containing %q, got nil", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("validateCerts() error = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func TestEnrollDevice_CredentialGenerationFailure(t *testing.T) {
	pkiProvider := &mockPKIProvider{
		deviceTrustBundleFn: func() *x509.CertPool { return x509.NewCertPool() },
		generateClientCredentialsFn: func() ([]byte, []byte, error) {
			return nil, nil, fmt.Errorf("vendor PKI engine credential failure")
		},
	}
	s := New(pkiProvider)
	req := &sutpb.EnrollDeviceRequest{
		IpAddress:        "127.0.0.1",
		Port:             "9999",
		ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}

	resp, err := s.EnrollDevice(context.Background(), req)
	if err == nil {
		t.Fatal("EnrollDevice() expected error, got nil")
	}
	if resp != nil {
		t.Errorf("EnrollDevice() resp = %v, want nil on dial failure", resp)
	}
	if !strings.Contains(err.Error(), "failed to generate client credentials") {
		t.Errorf("EnrollDevice() error = %v, want error containing 'failed to generate client credentials'", err)
	}
}

func TestEnrollDevice_MalformedClientCertificate(t *testing.T) {
	pkiProvider := &mockPKIProvider{
		deviceTrustBundleFn: func() *x509.CertPool { return x509.NewCertPool() },
		generateClientCredentialsFn: func() ([]byte, []byte, error) {
			return []byte("INVALID_CERT_PEM"), []byte("INVALID_KEY_PEM"), nil
		},
	}
	s := New(pkiProvider)
	req := &sutpb.EnrollDeviceRequest{
		IpAddress:        "127.0.0.1",
		Port:             "9999",
		ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}

	resp, err := s.EnrollDevice(context.Background(), req)
	if err == nil {
		t.Fatal("EnrollDevice() expected error, got nil")
	}
	if resp != nil {
		t.Errorf("EnrollDevice() resp = %v, want nil on dial failure", resp)
	}
	if !strings.Contains(err.Error(), "failed to parse client certificate") {
		t.Errorf("EnrollDevice() error = %v, want error containing 'failed to parse client certificate'", err)
	}
}

func TestEnrollDevice_EmptyControlCardRoles(t *testing.T) {
	s := New(&mockPKIProvider{})
	req := &sutpb.EnrollDeviceRequest{
		IpAddress: "127.0.0.1",
		Port:      "9999",
	}

	resp, err := s.EnrollDevice(context.Background(), req)
	if err == nil {
		t.Fatal("EnrollDevice() expected error for empty control_card_roles, got nil")
	}
	if resp != nil {
		t.Errorf("EnrollDevice() resp = %v, want nil", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("EnrollDevice() error code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
}

func TestIssueOwnerCerts_PKIFailure(t *testing.T) {
	mockPKI := &mockPKIProvider{
		issueOIAKFn: func(iakPem string) (string, error) {
			return "", fmt.Errorf("internal CA failure")
		},
	}
	s := New(mockPKI)
	iakResp := &epb.GetIakCertResponse{
		IakCert:    "TEST_IAK",
		IdevidCert: "TEST_IDEVID",
	}

	_, err := s.issueOwnerCerts(cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE, iakResp)
	if err == nil {
		t.Fatal("issueOwnerCerts() expected error, got nil")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("issueOwnerCerts() error code = %v, want %v", status.Code(err), codes.Internal)
	}
}
