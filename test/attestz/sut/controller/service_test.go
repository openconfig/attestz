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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	sutpb "github.com/openconfig/attestz/test/attestz/proto"
)

// mockPKIProvider implements PKIProvider for unit testing.
type mockPKIProvider struct {
	ownerTrustBundleFn          func() *x509.CertPool
	generateClientCredentialsFn func() ([]byte, []byte, error)
}

func (m *mockPKIProvider) OwnerTrustBundle() *x509.CertPool {
	if m.ownerTrustBundleFn != nil {
		return m.ownerTrustBundleFn()
	}
	return nil
}

func (m *mockPKIProvider) GenerateClientCredentials() ([]byte, []byte, error) {
	if m.generateClientCredentialsFn != nil {
		return m.generateClientCredentialsFn()
	}
	return nil, nil, nil
}

// mockPCRProvider implements PCRProvider for unit testing.
type mockPCRProvider struct {
	expectedPCRsFn func(ctx context.Context, device string) (map[int32][][]byte, error)
}

func (m *mockPCRProvider) ExpectedPCRs(ctx context.Context, device string) (map[int32][][]byte, error) {
	if m.expectedPCRsFn != nil {
		return m.expectedPCRsFn(ctx, device)
	}
	return nil, nil
}

// mockTPMCertUtils implements tpmutil.TPMCertUtils for unit testing.
type mockTPMCertUtils struct {
	toTPMTPublicFn func(cert *x509.Certificate) (*tpm2.TPMTPublic, error)
	isIAKFn        func(cert *x509.Certificate) (bool, error)
	isIDevIDFn     func(cert *x509.Certificate) (bool, error)
}

func (m *mockTPMCertUtils) ToTPMTPublic(cert *x509.Certificate) (*tpm2.TPMTPublic, error) {
	if m.toTPMTPublicFn != nil {
		return m.toTPMTPublicFn(cert)
	}
	return nil, nil
}

func (m *mockTPMCertUtils) IsIAK(cert *x509.Certificate) (bool, error) {
	if m.isIAKFn != nil {
		return m.isIAKFn(cert)
	}
	return true, nil
}

func (m *mockTPMCertUtils) IsIDevID(cert *x509.Certificate) (bool, error) {
	if m.isIDevIDFn != nil {
		return m.isIDevIDFn(cert)
	}
	return true, nil
}

func generateTestClientCredentials(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func TestAttestDevice_EmptyControlCardRoles(t *testing.T) {
	s := New(&mockPKIProvider{}, &mockPCRProvider{}, &mockTPMCertUtils{})
	req := &sutpb.AttestDeviceRequest{
		Host: "127.0.0.1",
		Port: "9999",
	}

	resp, err := s.AttestDevice(context.Background(), req)
	if err == nil {
		t.Fatal("AttestDevice() expected error for empty control_card_roles, got nil")
	}
	if resp != nil {
		t.Errorf("AttestDevice() resp = %v, want nil", resp)
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("AttestDevice() error code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
}

func TestAttestDevice_CredentialGenerationFailure(t *testing.T) {
	pkiProvider := &mockPKIProvider{
		ownerTrustBundleFn: x509.NewCertPool,
		generateClientCredentialsFn: func() ([]byte, []byte, error) {
			return nil, nil, fmt.Errorf("PKI client credentials generation error")
		},
	}
	s := New(pkiProvider, &mockPCRProvider{}, &mockTPMCertUtils{})
	req := &sutpb.AttestDeviceRequest{
		Host:             "127.0.0.1",
		Port:             "9999",
		ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}

	resp, err := s.AttestDevice(context.Background(), req)
	if err == nil {
		t.Fatal("AttestDevice() expected error, got nil")
	}
	if resp != nil {
		t.Errorf("AttestDevice() resp = %v, want nil on credential failure", resp)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("AttestDevice() error code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	if !strings.Contains(err.Error(), "failed to generate client credentials") {
		t.Errorf("AttestDevice() error = %v, want error containing 'failed to generate client credentials'", err)
	}
}

func TestAttestDevice_MalformedClientCertificate(t *testing.T) {
	pkiProvider := &mockPKIProvider{
		ownerTrustBundleFn: x509.NewCertPool,
		generateClientCredentialsFn: func() ([]byte, []byte, error) {
			return []byte("INVALID_CERT_PEM"), []byte("INVALID_KEY_PEM"), nil
		},
	}
	s := New(pkiProvider, &mockPCRProvider{}, &mockTPMCertUtils{})
	req := &sutpb.AttestDeviceRequest{
		Host:             "127.0.0.1",
		Port:             "9999",
		ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}

	resp, err := s.AttestDevice(context.Background(), req)
	if err == nil {
		t.Fatal("AttestDevice() expected error, got nil")
	}
	if resp != nil {
		t.Errorf("AttestDevice() resp = %v, want nil on cert parse failure", resp)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("AttestDevice() error code = %v, want %v", status.Code(err), codes.Unavailable)
	}
	if !strings.Contains(err.Error(), "failed to parse client certificate") {
		t.Errorf("AttestDevice() error = %v, want error containing 'failed to parse client certificate'", err)
	}
}

func TestAttestDevice_NoExpectedPCRs(t *testing.T) {
	certPEM, keyPEM := generateTestClientCredentials(t)
	pkiProvider := &mockPKIProvider{
		ownerTrustBundleFn: x509.NewCertPool,
		generateClientCredentialsFn: func() ([]byte, []byte, error) {
			return certPEM, keyPEM, nil
		},
	}
	pcrProvider := &mockPCRProvider{
		expectedPCRsFn: func(ctx context.Context, device string) (map[int32][][]byte, error) {
			return nil, fmt.Errorf("device profile not found")
		},
	}
	s := New(pkiProvider, pcrProvider, &mockTPMCertUtils{})
	req := &sutpb.AttestDeviceRequest{
		Host:             "127.0.0.1",
		Port:             "9999",
		ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
	}

	resp, err := s.AttestDevice(context.Background(), req)
	if err == nil {
		t.Fatal("AttestDevice() expected error when no expected PCRs, got nil")
	}
	if resp != nil {
		t.Errorf("AttestDevice() resp = %v, want nil on PCR provider failure", resp)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("AttestDevice() error code = %v, want %v", status.Code(err), codes.FailedPrecondition)
	}
	if !strings.Contains(err.Error(), "no expected PCRs found for device") {
		t.Errorf("AttestDevice() error = %v, want error containing 'no expected PCRs found for device'", err)
	}
}

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo cpb.Tpm20HashAlgo
		wantSize int
		wantErr  bool
	}{
		{
			name:     "SHA256",
			hashAlgo: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			wantSize: 32,
		},
		{
			name:     "SHA384",
			hashAlgo: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
			wantSize: 48,
		},
		{
			name:     "SHA512",
			hashAlgo: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA512,
			wantSize: 64,
		},
		{
			name:     "Unsupported hash algorithm",
			hashAlgo: cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_UNSPECIFIED,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nonce, err := generateNonce(tc.hashAlgo)
			if (err != nil) != tc.wantErr {
				t.Fatalf("generateNonce(%v) error = %v, wantErr %v", tc.hashAlgo, err, tc.wantErr)
			}
			if !tc.wantErr && len(nonce) != tc.wantSize {
				t.Errorf("len(generateNonce(%v)) = %d, want %d", tc.hashAlgo, len(nonce), tc.wantSize)
			}
		})
	}
}
