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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/attestz/service/biz"
)

type testOwnerCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestOwnerCA(t *testing.T) *testOwnerCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate CA serial number: %v", err)
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
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	return &testOwnerCA{cert: cert, key: key}
}

func (ca *testOwnerCA) signCert(cardID *cpb.ControlCardVendorId, pubPem string) (string, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	var subjectSerial string
	if cardID != nil {
		subjectSerial = cardID.GetControlCardSerial()
		if subjectSerial == "" {
			subjectSerial = cardID.GetChassisSerialNumber()
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subjectSerial,
			SerialNumber: subjectSerial,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pubKey, ca.key)
	if err != nil {
		return "", err
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})
	return string(certPem), nil
}

func (ca *testOwnerCA) IssueOwnerIakCert(_ context.Context, req *biz.IssueOwnerIakCertReq) (*biz.IssueOwnerIakCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.IakPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueOwnerIakCertResp{OwnerIakCertPem: certPem}, nil
}

func (ca *testOwnerCA) IssueOwnerIDevIDCert(_ context.Context, req *biz.IssueOwnerIDevIDCertReq) (*biz.IssueOwnerIDevIDCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.IDevIDPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: certPem}, nil
}

func (ca *testOwnerCA) IssueAikCert(_ context.Context, req *biz.IssueAikCertReq) (*biz.IssueAikCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.AikPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueAikCertResp{AikCertPem: certPem}, nil
}

func (ca *testOwnerCA) issueClientTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client TLS key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "test-enrollz-client",
			Organization: []string{"Switch Owner"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to sign client TLS cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDer, ca.cert.Raw},
		PrivateKey:  key,
	}
}

type testDeviceClient struct {
	client epb.TpmEnrollzServiceClient
}

func (d *testDeviceClient) GetIakCert(ctx context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	return d.client.GetIakCert(ctx, req)
}

func (d *testDeviceClient) RotateOIakCert(ctx context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	return d.client.RotateOIakCert(ctx, req)
}

func (d *testDeviceClient) RotateAIKCert(ctx context.Context, opts ...grpc.CallOption) (epb.TpmEnrollzService_RotateAIKCertClient, error) {
	return d.client.RotateAIKCert(ctx, opts...)
}

func (d *testDeviceClient) GetControlCardVendorID(ctx context.Context, req *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error) {
	return d.client.GetControlCardVendorID(ctx, req)
}

func (d *testDeviceClient) Challenge(ctx context.Context, req *epb.ChallengeRequest) (*epb.ChallengeResponse, error) {
	return d.client.Challenge(ctx, req)
}

func (d *testDeviceClient) GetIdevidCsr(ctx context.Context, req *epb.GetIdevidCsrRequest) (*epb.GetIdevidCsrResponse, error) {
	return d.client.GetIdevidCsr(ctx, req)
}

type testEnrollzDeps struct {
	biz.SwitchOwnerCaClient
	biz.EnrollzDeviceClient
	biz.TpmCertVerifier
}

func TestNewDeviceServer(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() returned unexpected error: %v", err)
	}
	if server.CaCertPem() == "" {
		t.Errorf("CaCertPem() returned empty string")
	}
	if server.ActiveCard() == nil {
		t.Errorf("ActiveCard() returned nil")
	}
	if server.StandbyCard() == nil {
		t.Errorf("StandbyCard() returned nil")
	}
}

func TestGetIakCert(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() failed: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(server.CaCertPem())) {
		t.Fatalf("failed to append CA cert to pool")
	}

	ctx := context.Background()

	tests := []struct {
		desc      string
		selection *cpb.ControlCardSelection
		wantRole  cpb.ControlCardRole
		wantSlot  string
	}{
		{
			desc: "Active role selection",
			selection: &cpb.ControlCardSelection{
				ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
			},
			wantRole: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			wantSlot: "slot-1",
		},
		{
			desc: "Standby role selection",
			selection: &cpb.ControlCardSelection{
				ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY},
			},
			wantRole: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
			wantSlot: "slot-2",
		},
		{
			desc: "Serial selection active",
			selection: &cpb.ControlCardSelection{
				ControlCardId: &cpb.ControlCardSelection_Serial{Serial: "card-serial-active-1"},
			},
			wantRole: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
			wantSlot: "slot-1",
		},
		{
			desc: "Slot selection standby",
			selection: &cpb.ControlCardSelection{
				ControlCardId: &cpb.ControlCardSelection_Slot{Slot: "slot-2"},
			},
			wantRole: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
			wantSlot: "slot-2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			resp, err := server.GetIakCert(ctx, &epb.GetIakCertRequest{ControlCardSelection: tc.selection})
			if err != nil {
				t.Fatalf("GetIakCert() failed: %v", err)
			}
			if resp.GetControlCardId().GetControlCardRole() != tc.wantRole {
				t.Errorf("GetControlCardRole() = %v, want %v", resp.GetControlCardId().GetControlCardRole(), tc.wantRole)
			}
			if resp.GetControlCardId().GetControlCardSlot() != tc.wantSlot {
				t.Errorf("GetControlCardSlot() = %v, want %v", resp.GetControlCardId().GetControlCardSlot(), tc.wantSlot)
			}
			if !resp.GetAtomicCertRotationSupported() {
				t.Errorf("AtomicCertRotationSupported = false, want true")
			}
			if resp.GetIakCert() == "" || resp.GetIdevidCert() == "" {
				t.Errorf("IakCert or IdevidCert is empty")
			}
		})
	}
}

func TestRotateOIakCert(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() failed: %v", err)
	}

	ctx := context.Background()

	// Test atomic rotation
	atomicReq := &epb.RotateOIakCertRequest{
		SslProfileId: "test-ssl-profile",
		Updates: []*epb.ControlCardCertUpdate{
			{
				ControlCardSelection: &cpb.ControlCardSelection{
					ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
				},
				OiakCert:    "test-active-oiak-pem",
				OidevidCert: "test-active-oidevid-pem",
			},
			{
				ControlCardSelection: &cpb.ControlCardSelection{
					ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY},
				},
				OiakCert:    "test-standby-oiak-pem",
				OidevidCert: "test-standby-oidevid-pem",
			},
		},
	}

	_, err = server.RotateOIakCert(ctx, atomicReq)
	if err != nil {
		t.Fatalf("RotateOIakCert() atomic failed: %v", err)
	}

	if server.SslProfileID() != "test-ssl-profile" {
		t.Errorf("SslProfileID() = %q, want %q", server.SslProfileID(), "test-ssl-profile")
	}
	if server.ActiveCard().OwnerIakCertPem != "test-active-oiak-pem" {
		t.Errorf("ActiveCard().OwnerIakCertPem = %q, want %q", server.ActiveCard().OwnerIakCertPem, "test-active-oiak-pem")
	}
	if server.StandbyCard().OwnerIdevidCertPem != "test-standby-oidevid-pem" {
		t.Errorf("StandbyCard().OwnerIdevidCertPem = %q, want %q", server.StandbyCard().OwnerIdevidCertPem, "test-standby-oidevid-pem")
	}

	// Test single card rotation
	singleReq := &epb.RotateOIakCertRequest{
		SslProfileId: "single-ssl-profile",
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
		},
		OiakCert:    "updated-active-oiak-pem",
		OidevidCert: "updated-active-oidevid-pem",
	}
	_, err = server.RotateOIakCert(ctx, singleReq)
	if err != nil {
		t.Fatalf("RotateOIakCert() single failed: %v", err)
	}
	if server.ActiveCard().OwnerIakCertPem != "updated-active-oiak-pem" {
		t.Errorf("ActiveCard().OwnerIakCertPem = %q, want %q", server.ActiveCard().OwnerIakCertPem, "updated-active-oiak-pem")
	}
}

func TestGetControlCardVendorID(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() failed: %v", err)
	}

	ctx := context.Background()
	resp, err := server.GetControlCardVendorID(ctx, &epb.GetControlCardVendorIDRequest{
		ControlCardSelection: &cpb.ControlCardSelection{
			ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY},
		},
	})
	if err != nil {
		t.Fatalf("GetControlCardVendorID() failed: %v", err)
	}
	if resp.GetControlCardId().GetControlCardRole() != cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY {
		t.Errorf("GetControlCardRole() = %v, want %v", resp.GetControlCardId().GetControlCardRole(), cpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY)
	}
}

func TestEnrollzAgainstDeviceServer(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() failed: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	epb.RegisterTpmEnrollzServiceServer(grpcServer, server)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect to device server: %v", err)
	}
	defer conn.Close()

	devClient := &testDeviceClient{client: epb.NewTpmEnrollzServiceClient(conn)}
	ownerCa := newTestOwnerCA(t)

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(server.CaCertPem())) {
		t.Fatalf("failed to add vendor CA to pool")
	}

	deps := &testEnrollzDeps{
		SwitchOwnerCaClient: ownerCa,
		EnrollzDeviceClient: devClient,
		TpmCertVerifier:     &biz.DefaultTpmCertVerifier{},
	}

	req := &biz.EnrollControlCardReq{
		ControlCardSelections: []*cpb.ControlCardSelection{
			{
				ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
			},
		},
		Deps:                 deps,
		CertVerificationOpts: x509.VerifyOptions{Roots: caPool},
		SSLProfileID:         "ssl_profile_id",
	}

	ctx := context.Background()
	if err := biz.EnrollControlCard(ctx, req); err != nil {
		t.Fatalf("EnrollControlCard() failed: %v", err)
	}

	if server.ActiveCard().OwnerIakCertPem == "" {
		t.Errorf("ActiveCard().OwnerIakCertPem is empty after enrollment")
	}
	if server.ActiveCard().OwnerIdevidCertPem == "" {
		t.Errorf("ActiveCard().OwnerIdevidCertPem is empty after enrollment")
	}
}

func TestEnrollzAgainstDeviceServerMTLS(t *testing.T) {
	server, err := NewDeviceServer()
	if err != nil {
		t.Fatalf("NewDeviceServer() failed: %v", err)
	}

	ownerCa := newTestOwnerCA(t)
	ownerPool := x509.NewCertPool()
	ownerPool.AddCert(ownerCa.cert)

	serverCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{server.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ownerPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer(grpc.Creds(serverCreds))
	epb.RegisterTpmEnrollzServiceServer(grpcServer, server)
	go grpcServer.Serve(lis)
	defer grpcServer.Stop()

	vendorPool := x509.NewCertPool()
	if !vendorPool.AppendCertsFromPEM([]byte(server.CaCertPem())) {
		t.Fatalf("failed to add vendor CA to pool")
	}

	clientTLSCert := ownerCa.issueClientTLSCert(t)
	clientCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      vendorPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		t.Fatalf("failed to connect to device server: %v", err)
	}
	defer conn.Close()

	devClient := &testDeviceClient{client: epb.NewTpmEnrollzServiceClient(conn)}
	deps := &testEnrollzDeps{
		SwitchOwnerCaClient: ownerCa,
		EnrollzDeviceClient: devClient,
		TpmCertVerifier:     &biz.DefaultTpmCertVerifier{},
	}

	req := &biz.EnrollControlCardReq{
		ControlCardSelections: []*cpb.ControlCardSelection{
			{
				ControlCardId: &cpb.ControlCardSelection_Role{Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
			},
		},
		Deps:                 deps,
		CertVerificationOpts: x509.VerifyOptions{Roots: vendorPool},
		SSLProfileID:         "ssl_profile_id",
	}

	ctx := context.Background()
	if err := biz.EnrollControlCard(ctx, req); err != nil {
		t.Fatalf("EnrollControlCard() failed: %v", err)
	}

	if server.ActiveCard().OwnerIakCertPem == "" {
		t.Errorf("ActiveCard().OwnerIakCertPem is empty after enrollment")
	}
	if server.ActiveCard().OwnerIdevidCertPem == "" {
		t.Errorf("ActiveCard().OwnerIdevidCertPem is empty after enrollment")
	}
}
