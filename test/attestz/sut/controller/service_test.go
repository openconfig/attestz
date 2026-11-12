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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	apb "github.com/openconfig/attestz/proto/tpm_attestz"
	sutpb "github.com/openconfig/attestz/test/attestz/proto"
)

type mockAttestzClient struct {
	apb.TpmAttestzServiceClient
	attestFn func(ctx context.Context, in *apb.AttestRequest, opts ...grpc.CallOption) (*apb.AttestResponse, error)
}

func (m *mockAttestzClient) Attest(ctx context.Context, in *apb.AttestRequest, opts ...grpc.CallOption) (*apb.AttestResponse, error) {
	return m.attestFn(ctx, in, opts...)
}

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

func generateTestCertPEMWithEKU(t *testing.T, priv crypto.Signer, extKeyUsage []x509.ExtKeyUsage) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test oIAK"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           extKeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func createMockRSATPMTPublic(pub *rsa.PublicKey) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits:  2048,
				Exponent: uint32(pub.E),
				Scheme: tpm2.TPMTRSAScheme{
					Scheme:  tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: pub.N.Bytes()},
		),
	}
}

func createMockECDSATPMTPublic(t *testing.T, pub *ecdsa.PublicKey) *tpm2.TPMTPublic {
	t.Helper()
	coordLen := (pub.Curve.Params().BitSize + 7) / 8
	pubBytes, err := pub.Bytes()
	if err != nil || len(pubBytes) != 2*coordLen+1 {
		t.Fatalf("pub.Bytes() len = %d, err = %v", len(pubBytes), err)
	}
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA384,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP384,
				Scheme: tpm2.TPMTECCScheme{
					Scheme:  tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA384}),
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: pubBytes[1 : 1+coordLen]},
				Y: tpm2.TPM2BECCParameter{Buffer: pubBytes[1+coordLen:]},
			},
		),
	}
}

func buildSimulatedQuoteAndSig(t *testing.T, priv crypto.Signer, pcr0Val, nonce []byte, hashAlgo cpb.Tpm20HashAlgo) ([]byte, []byte) {
	t.Helper()
	var (
		tpmHash    tpm2.TPMIAlgHash
		cryptoHash crypto.Hash
		pcrDigest  []byte
	)
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		tpmHash = tpm2.TPMAlgSHA256
		cryptoHash = crypto.SHA256
		sum := sha256.Sum256(pcr0Val)
		pcrDigest = sum[:]
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		tpmHash = tpm2.TPMAlgSHA384
		cryptoHash = crypto.SHA384
		sum := sha512.Sum384(pcr0Val)
		pcrDigest = sum[:]
	default:
		t.Fatalf("unsupported hash algorithm %v", hashAlgo)
	}

	attest := tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("dummy_signer")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(
			tpm2.TPMSTAttestQuote,
			&tpm2.TPMSQuoteInfo{
				PCRSelect: tpm2.TPMLPCRSelection{
					PCRSelections: []tpm2.TPMSPCRSelection{
						{
							Hash:      tpmHash,
							PCRSelect: []byte{0x01, 0x00, 0x00}, // PCR 0
						},
					},
				},
				PCRDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
			},
		),
	}
	quoted := tpm2.Marshal(attest)

	var quotedHash []byte
	switch hashAlgo {
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256:
		sum := sha256.Sum256(quoted)
		quotedHash = sum[:]
	case cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384:
		sum := sha512.Sum384(quoted)
		quotedHash = sum[:]
	}

	var tpmSig tpm2.TPMTSignature
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		sigBytes, err := rsa.SignPKCS1v15(rand.Reader, k, cryptoHash, quotedHash)
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15() error: %v", err)
		}
		tpmSig = tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpmHash,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sigBytes},
				},
			),
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, quotedHash)
		if err != nil {
			t.Fatalf("ecdsa.Sign() error: %v", err)
		}
		tpmSig = tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpmHash,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
				},
			),
		}
	default:
		t.Fatalf("unsupported signer type %T", priv)
	}
	return quoted, tpm2.Marshal(tpmSig)
}

func TestAttestControlCard_OIAKVerification(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error: %v", err)
	}
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error: %v", err)
	}
	// Generate RSA and ECDSA oIAK certificates without ExtKeyUsageServerAuth (only ExtKeyUsageClientAuth).
	rsaNoServerAuthOIAKPEM := generateTestCertPEMWithEKU(t, rsaPriv, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	ecdsaNoServerAuthOIAKPEM := generateTestCertPEMWithEKU(t, ecdsaPriv, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	untrustedPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error: %v", err)
	}
	untrustedOIAKPEM := generateTestCertPEMWithEKU(t, untrustedPriv, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	trustedPool := x509.NewCertPool()
	if !trustedPool.AppendCertsFromPEM([]byte(rsaNoServerAuthOIAKPEM)) {
		t.Fatal("Failed to append RSA test oIAK cert to trusted pool")
	}
	if !trustedPool.AppendCertsFromPEM([]byte(ecdsaNoServerAuthOIAKPEM)) {
		t.Fatal("Failed to append ECDSA test oIAK cert to trusted pool")
	}

	pcr0Val := []byte("golden_pcr0_value")
	expectedPCRs := map[int32][][]byte{0: {pcr0Val}}
	sortedIndices := []int32{0}
	pkiProvider := &mockPKIProvider{
		ownerTrustBundleFn: func() *x509.CertPool {
			return trustedPool
		},
	}
	rsaTPMPublic := createMockRSATPMTPublic(&rsaPriv.PublicKey)
	ecdsaTPMPublic := createMockECDSATPMTPublic(t, &ecdsaPriv.PublicKey)

	tests := []struct {
		name       string
		oiakPEM    string
		priv       crypto.Signer
		tpmPublic  *tpm2.TPMTPublic
		hashAlgo   cpb.Tpm20HashAlgo
		isIAK      bool
		wantCode   codes.Code
		wantMsgSub string
	}{
		{
			name:      "Valid RSA oIAK without ServerAuth EKU (SHA-256)",
			oiakPEM:   rsaNoServerAuthOIAKPEM,
			priv:      rsaPriv,
			tpmPublic: rsaTPMPublic,
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			isIAK:     true,
			wantCode:  codes.OK,
		},
		{
			name:      "Valid ECDSA oIAK without ServerAuth EKU (SHA-384)",
			oiakPEM:   ecdsaNoServerAuthOIAKPEM,
			priv:      ecdsaPriv,
			tpmPublic: ecdsaTPMPublic,
			hashAlgo:  cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
			isIAK:     true,
			wantCode:  codes.OK,
		},
		{
			name:       "Untrusted oIAK certificate",
			oiakPEM:    untrustedOIAKPEM,
			priv:       rsaPriv,
			tpmPublic:  rsaTPMPublic,
			hashAlgo:   cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			isIAK:      true,
			wantCode:   codes.FailedPrecondition,
			wantMsgSub: "oIAK certificate verification failed",
		},
		{
			name:       "Invalid oIAK certificate (IsIAK=false)",
			oiakPEM:    rsaNoServerAuthOIAKPEM,
			priv:       rsaPriv,
			tpmPublic:  rsaTPMPublic,
			hashAlgo:   cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256,
			isIAK:      false,
			wantCode:   codes.FailedPrecondition,
			wantMsgSub: "certificate is not a valid oIAK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &sutpb.AttestDeviceRequest{
				Host:             "127.0.0.1",
				Port:             "9339",
				ControlCardRoles: []cpb.ControlCardRole{cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
				HashAlgo:         tc.hashAlgo,
			}
			tpmCertUtils := &mockTPMCertUtils{
				isIAKFn: func(cert *x509.Certificate) (bool, error) {
					return tc.isIAK, nil
				},
				toTPMTPublicFn: func(cert *x509.Certificate) (*tpm2.TPMTPublic, error) {
					return tc.tpmPublic, nil
				},
			}
			s := New(pkiProvider, &mockPCRProvider{}, tpmCertUtils)

			client := &mockAttestzClient{
				attestFn: func(ctx context.Context, in *apb.AttestRequest, opts ...grpc.CallOption) (*apb.AttestResponse, error) {
					quoted, sig := buildSimulatedQuoteAndSig(t, tc.priv, pcr0Val, in.GetNonce(), tc.hashAlgo)
					return &apb.AttestResponse{
						AttestationCert: &apb.AttestResponse_AttestationCert{
							Value: &apb.AttestResponse_AttestationCert_OiakCert{
								OiakCert: tc.oiakPEM,
							},
						},
						Quoted:         quoted,
						QuoteSignature: sig,
						PcrValues:      map[int32][]byte{0: pcr0Val},
					}, nil
				},
			}

			gotStatus := s.attestControlCard(context.Background(), client, req, cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE, expectedPCRs, sortedIndices)
			if codes.Code(gotStatus.GetCode()) != tc.wantCode {
				t.Errorf("attestControlCard() code = %v, want %v (msg: %q)", codes.Code(gotStatus.GetCode()), tc.wantCode, gotStatus.GetMessage())
			}
			if tc.wantMsgSub != "" && !strings.Contains(gotStatus.GetMessage(), tc.wantMsgSub) {
				t.Errorf("attestControlCard() msg = %q, want substring %q", gotStatus.GetMessage(), tc.wantMsgSub)
			}
		})
	}
}
