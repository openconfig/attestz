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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/attestz/service/biz"
)

func generateTestKeyPem(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(block)
}

func generateTestOwnerCACertAndKey(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Switch Owner CA"},
			CommonName:   "Switch Owner Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	keyDer, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "owner_ca_cert.pem")
	keyPath := filepath.Join(dir, "owner_ca_key.pem")

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})
	if err := os.WriteFile(certPath, certPem, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer,
	})
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return certPath, keyPath
}

func TestOwnerCA(t *testing.T) {
	certPath, keyPath := generateTestOwnerCACertAndKey(t)
	ca, err := newOwnerCA(certPath, keyPath, "127.0.0.1")
	if err != nil {
		t.Fatalf("newOwnerCA() returned unexpected error: %v", err)
	}

	pubPem := generateTestKeyPem(t)
	cardID := &cpb.ControlCardVendorId{
		ControlCardSerial:   "test-card-serial",
		ChassisSerialNumber: "test-chassis-serial",
	}

	ctx := context.Background()

	// Test IssueOwnerIakCert
	iakResp, err := ca.IssueOwnerIakCert(ctx, &biz.IssueOwnerIakCertReq{
		CardID:    cardID,
		IakPubPem: pubPem,
	})
	if err != nil {
		t.Fatalf("IssueOwnerIakCert() failed: %v", err)
	}
	if iakResp.OwnerIakCertPem == "" {
		t.Errorf("IssueOwnerIakCert() returned empty cert PEM")
	}

	// Test IssueOwnerIDevIDCert
	idevidResp, err := ca.IssueOwnerIDevIDCert(ctx, &biz.IssueOwnerIDevIDCertReq{
		CardID:       cardID,
		IDevIDPubPem: pubPem,
	})
	if err != nil {
		t.Fatalf("IssueOwnerIDevIDCert() failed: %v", err)
	}
	if idevidResp.OwnerIDevIDCertPem == "" {
		t.Errorf("IssueOwnerIDevIDCert() returned empty cert PEM")
	}

	// Test IssueAikCert
	aikResp, err := ca.IssueAikCert(ctx, &biz.IssueAikCertReq{
		CardID:    cardID,
		AikPubPem: pubPem,
	})
	if err != nil {
		t.Fatalf("IssueAikCert() failed: %v", err)
	}
	if aikResp.AikCertPem == "" {
		t.Errorf("IssueAikCert() returned empty cert PEM")
	}

	// Verify SAN contains default clientIP
	verifyCertSAN := func(certPem, certName string) {
		t.Helper()
		block, _ := pem.Decode([]byte(certPem))
		if block == nil {
			t.Fatalf("%s failed to decode cert PEM", certName)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s failed to parse cert: %v", certName, err)
		}
		if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
			t.Errorf("%s IPAddresses = %v, want [127.0.0.1]", certName, cert.IPAddresses)
		}
	}
	verifyCertSAN(iakResp.OwnerIakCertPem, "OwnerIakCert")
	verifyCertSAN(idevidResp.OwnerIDevIDCertPem, "OwnerIDevIDCert")
	verifyCertSAN(aikResp.AikCertPem, "AikCert")

	// Test issueClientTLSCert
	tlsCert, err := ca.issueClientTLSCert()
	if err != nil {
		t.Fatalf("issueClientTLSCert() failed: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Errorf("issueClientTLSCert() returned empty certificate chain")
	}
}

func TestSignCertSubjectAlternateName(t *testing.T) {
	certPath, keyPath := generateTestOwnerCACertAndKey(t)
	pubPem := generateTestKeyPem(t)
	cardID := &cpb.ControlCardVendorId{ControlCardSerial: "test-card-serial"}

	tests := []struct {
		name        string
		clientIPVal string
		wantIPs     []string
	}{
		{
			name:        "IPv4 address",
			clientIPVal: "192.168.1.100",
			wantIPs:     []string{"192.168.1.100"},
		},
		{
			name:        "IPv6 address",
			clientIPVal: "2001:db8::1",
			wantIPs:     []string{"2001:db8::1"},
		},
		{
			name:        "IPv6 loopback",
			clientIPVal: "::1",
			wantIPs:     []string{"::1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := newOwnerCA(certPath, keyPath, tc.clientIPVal)
			if err != nil {
				t.Fatalf("newOwnerCA() failed: %v", err)
			}
			certPem, err := ca.signCert(cardID, pubPem)
			if err != nil {
				t.Fatalf("signCert() failed: %v", err)
			}
			block, _ := pem.Decode([]byte(certPem))
			if block == nil {
				t.Fatalf("failed to decode cert PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse cert: %v", err)
			}

			if len(tc.wantIPs) == 0 {
				if len(cert.IPAddresses) != 0 {
					t.Errorf("cert.IPAddresses = %v, want empty", cert.IPAddresses)
				}
			} else {
				if len(cert.IPAddresses) != len(tc.wantIPs) {
					t.Fatalf("cert.IPAddresses length = %d, want %d", len(cert.IPAddresses), len(tc.wantIPs))
				}
				for i, wantIP := range tc.wantIPs {
					if !cert.IPAddresses[i].Equal(net.ParseIP(wantIP)) {
						t.Errorf("cert.IPAddresses[%d] = %v, want %s", i, cert.IPAddresses[i], wantIP)
					}
				}
			}
		})
	}
}

func TestNewOwnerCAErrors(t *testing.T) {
	certPath, keyPath := generateTestOwnerCACertAndKey(t)
	if _, err := newOwnerCA("nonexistent_cert.pem", keyPath, "127.0.0.1"); err == nil {
		t.Errorf("newOwnerCA() with nonexistent cert should fail, got nil")
	}
	if _, err := newOwnerCA(certPath, "nonexistent_key.pem", "127.0.0.1"); err == nil {
		t.Errorf("newOwnerCA() with nonexistent key should fail, got nil")
	}
	if _, err := newOwnerCA(certPath, keyPath, "invalid-ip"); err == nil {
		t.Errorf("newOwnerCA() with invalid IP should fail, got nil")
	}
	if _, err := newOwnerCA(certPath, keyPath, ""); err == nil {
		t.Errorf("newOwnerCA() with empty IP should fail, got nil")
	}
}

func TestFlags(t *testing.T) {
	portFlag := flag.Lookup("port")
	if portFlag == nil {
		t.Fatal("flag --port is not defined")
	}
	if portFlag.DefValue != "4321" {
		t.Errorf("--port default value = %q, want %q", portFlag.DefValue, "4321")
	}
}

func TestParsePrivateKey(t *testing.T) {
	// 1. SEC 1 EC Private Key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	sec1Der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal SEC1 EC key: %v", err)
	}
	if parsedKey, err := parsePrivateKey(sec1Der); err != nil {
		t.Errorf("parsePrivateKey(sec1Der) failed: %v", err)
	} else if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("parsedKey type = %T, want *ecdsa.PrivateKey", parsedKey)
	}

	// 2. PKCS#8 EC Private Key
	pkcs8ECDer, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 EC key: %v", err)
	}
	if parsedKey, err := parsePrivateKey(pkcs8ECDer); err != nil {
		t.Errorf("parsePrivateKey(pkcs8ECDer) failed: %v", err)
	} else if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("parsedKey type = %T, want *ecdsa.PrivateKey", parsedKey)
	}

	// 3. PKCS#1 RSA Private Key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pkcs1Der := x509.MarshalPKCS1PrivateKey(rsaKey)
	if parsedKey, err := parsePrivateKey(pkcs1Der); err != nil {
		t.Errorf("parsePrivateKey(pkcs1Der) failed: %v", err)
	} else if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Errorf("parsedKey type = %T, want *rsa.PrivateKey", parsedKey)
	}

	// 4. PKCS#8 RSA Private Key
	pkcs8RSADer, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 RSA key: %v", err)
	}
	if parsedKey, err := parsePrivateKey(pkcs8RSADer); err != nil {
		t.Errorf("parsePrivateKey(pkcs8RSADer) failed: %v", err)
	} else if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Errorf("parsedKey type = %T, want *rsa.PrivateKey", parsedKey)
	}

	// 5. PKCS#8 Ed25519 Private Key
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	pkcs8EdDer, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 Ed25519 key: %v", err)
	}
	if parsedKey, err := parsePrivateKey(pkcs8EdDer); err != nil {
		t.Errorf("parsePrivateKey(pkcs8EdDer) failed: %v", err)
	} else if _, ok := parsedKey.(ed25519.PrivateKey); !ok {
		t.Errorf("parsedKey type = %T, want ed25519.PrivateKey", parsedKey)
	}

	// 6. Invalid DER
	if _, err := parsePrivateKey([]byte("invalid DER bytes")); err == nil {
		t.Errorf("parsePrivateKey(invalid) expected error, got nil")
	}
}

type mockDeviceServer struct {
	epb.UnimplementedTpmEnrollzServiceServer

	getIakCertResp *epb.GetIakCertResponse
	rotateOIakResp *epb.RotateOIakCertResponse
	rotateOIakReq  *epb.RotateOIakCertRequest
	vendorIDResp   *epb.GetControlCardVendorIDResponse
	challengeResp  *epb.ChallengeResponse
	idevidCsrResp  *epb.GetIdevidCsrResponse
}

func (m *mockDeviceServer) GetIakCert(_ context.Context, _ *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	return m.getIakCertResp, nil
}

func (m *mockDeviceServer) RotateOIakCert(_ context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	m.rotateOIakReq = req
	return m.rotateOIakResp, nil
}

func (m *mockDeviceServer) GetControlCardVendorID(_ context.Context, _ *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error) {
	return m.vendorIDResp, nil
}

func (m *mockDeviceServer) Challenge(_ context.Context, _ *epb.ChallengeRequest) (*epb.ChallengeResponse, error) {
	return m.challengeResp, nil
}

func (m *mockDeviceServer) GetIdevidCsr(_ context.Context, _ *epb.GetIdevidCsrRequest) (*epb.GetIdevidCsrResponse, error) {
	return m.idevidCsrResp, nil
}

func TestDeviceClient(t *testing.T) {
	mockServer := &mockDeviceServer{
		getIakCertResp: &epb.GetIakCertResponse{
			ControlCardId: &cpb.ControlCardVendorId{ControlCardSerial: "test-serial"},
		},
		rotateOIakResp: &epb.RotateOIakCertResponse{},
		vendorIDResp: &epb.GetControlCardVendorIDResponse{
			ControlCardId: &cpb.ControlCardVendorId{ControlCardSerial: "test-serial"},
		},
		challengeResp: &epb.ChallengeResponse{},
		idevidCsrResp: &epb.GetIdevidCsrResponse{},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	epb.RegisterTpmEnrollzServiceServer(grpcServer, mockServer)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := &deviceClient{client: epb.NewTpmEnrollzServiceClient(conn)}
	ctx := context.Background()

	// Verify GetIakCert
	iakResp, err := client.GetIakCert(ctx, &epb.GetIakCertRequest{})
	if err != nil {
		t.Errorf("GetIakCert() failed: %v", err)
	}
	if iakResp.GetControlCardId().GetControlCardSerial() != "test-serial" {
		t.Errorf("GetControlCardSerial() = %q, want %q", iakResp.GetControlCardId().GetControlCardSerial(), "test-serial")
	}

	// Verify RotateOIakCert with deprecated fields
	deprecatedReq := &epb.RotateOIakCertRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
		},
		OiakCert:     "test-oiak-cert",
		OidevidCert:  "test-oidevid-cert",
		SslProfileId: "test-profile",
	}
	rotateResp, err := client.RotateOIakCert(ctx, deprecatedReq)
	if err != nil {
		t.Errorf("RotateOIakCert() failed: %v", err)
	}
	if rotateResp == nil {
		t.Errorf("RotateOIakCert() returned nil response")
	}
	if got := mockServer.rotateOIakReq.GetOiakCert(); got != "test-oiak-cert" {
		t.Errorf("GetOiakCert() = %q, want %q", got, "test-oiak-cert")
	}
	if got := mockServer.rotateOIakReq.GetOidevidCert(); got != "test-oidevid-cert" {
		t.Errorf("GetOidevidCert() = %q, want %q", got, "test-oidevid-cert")
	}
	if gotRole := mockServer.rotateOIakReq.GetControlCardSelection().GetRole(); gotRole != cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE {
		t.Errorf("GetRole() = %v, want %v", gotRole, cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE)
	}

	// Verify RotateOIakCert with updates already set
	updatesReq := &epb.RotateOIakCertRequest{
		Updates: []*epb.ControlCardCertUpdate{
			{
				ControlCardSelection: &cpb.ControlCardSelection{
					ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY},
				},
				OiakCert: "standby-oiak-cert",
			},
		},
	}
	rotateResp2, err := client.RotateOIakCert(ctx, updatesReq)
	if err != nil {
		t.Errorf("RotateOIakCert() with updates failed: %v", err)
	}
	if rotateResp2 == nil {
		t.Errorf("RotateOIakCert() returned nil response")
	}
	if gotUpdates := mockServer.rotateOIakReq.GetUpdates(); len(gotUpdates) != 1 {
		t.Errorf("RotateOIakCert() got %d updates, want 1", len(gotUpdates))
	} else if gotUpdates[0].GetOiakCert() != "standby-oiak-cert" {
		t.Errorf("GetOiakCert() = %q, want %q", gotUpdates[0].GetOiakCert(), "standby-oiak-cert")
	}

	// Verify GetControlCardVendorID
	vendorResp, err := client.GetControlCardVendorID(ctx, &epb.GetControlCardVendorIDRequest{})
	if err != nil {
		t.Errorf("GetControlCardVendorID() failed: %v", err)
	}
	if vendorResp.GetControlCardId().GetControlCardSerial() != "test-serial" {
		t.Errorf("GetControlCardVendorID() returned wrong serial: %v", vendorResp)
	}

	// Verify Challenge
	challengeResp, err := client.Challenge(ctx, &epb.ChallengeRequest{})
	if err != nil {
		t.Errorf("Challenge() failed: %v", err)
	}
	if challengeResp == nil {
		t.Errorf("Challenge() returned nil response")
	}

	// Verify GetIdevidCsr
	csrResp, err := client.GetIdevidCsr(ctx, &epb.GetIdevidCsrRequest{})
	if err != nil {
		t.Errorf("GetIdevidCsr() failed: %v", err)
	}
	if csrResp == nil {
		t.Errorf("GetIdevidCsr() returned nil response")
	}
}
