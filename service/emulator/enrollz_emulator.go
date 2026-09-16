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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	log "github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
	"github.com/openconfig/attestz/service/biz"
)

var (
	vendorCATrustBundle = flag.String("vendor_ca_trust_bundle", "", "Path to switch vendor CA trust bundle PEM file")
	clientIP            = flag.String("client_ip", "127.0.0.1", "IP address of the switch device")
	port                = flag.String("port", "4321", "Port of the switch device")
	ownerCACert         = flag.String("owner_ca_cert", "service/emulator/owner_ca_cert.pem", "Path to switch owner CA certificate PEM file")
	ownerCAKey          = flag.String("owner_ca_key", "service/emulator/owner_ca_key.pem", "Path to switch owner CA private key PEM file")
)

type ownerCA struct {
	cert     *x509.Certificate
	key      crypto.PrivateKey
	clientIP net.IP
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		base := filepath.Base(path)
		if data2, err2 := os.ReadFile(base); err2 == nil {
			return data2, nil
		}
		if data2, err2 := os.ReadFile(filepath.Join("service", "emulator", base)); err2 == nil {
			return data2, nil
		}
	}
	return nil, err
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key: unsupported key format or corrupted DER")
}

func newOwnerCA(certFile, keyFile, clientIP string) (*ownerCA, error) {
	certBytes, err := readFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read owner CA cert file: %w", err)
	}
	keyBytes, err := readFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read owner CA key file: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, errors.New("failed to decode owner CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse owner CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, errors.New("failed to decode owner CA key PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse owner CA private key: %w", err)
	}
	if clientIP == "" {
		return nil, errors.New("client IP cannot be empty")
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse client IP %q: invalid IP address", clientIP)
	}
	return &ownerCA{cert: cert, key: key, clientIP: ip}, nil
}

func (ca *ownerCA) signCert(cardID *cpb.ControlCardVendorId, pubPem string) (string, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return "", errors.New("failed to decode PEM block containing public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
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
		IPAddresses:           []net.IP{ca.clientIP},
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pubKey, ca.key)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})
	return string(certPem), nil
}

func (ca *ownerCA) IssueOwnerIakCert(_ context.Context, req *biz.IssueOwnerIakCertReq) (*biz.IssueOwnerIakCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.IakPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueOwnerIakCertResp{OwnerIakCertPem: certPem}, nil
}

func (ca *ownerCA) IssueOwnerIDevIDCert(_ context.Context, req *biz.IssueOwnerIDevIDCertReq) (*biz.IssueOwnerIDevIDCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.IDevIDPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueOwnerIDevIDCertResp{OwnerIDevIDCertPem: certPem}, nil
}

func (ca *ownerCA) IssueAikCert(_ context.Context, req *biz.IssueAikCertReq) (*biz.IssueAikCertResp, error) {
	certPem, err := ca.signCert(req.CardID, req.AikPubPem)
	if err != nil {
		return nil, err
	}
	return &biz.IssueAikCertResp{AikCertPem: certPem}, nil
}

func (ca *ownerCA) issueClientTLSCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate client TLS key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "enrollz-client",
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
		return tls.Certificate{}, fmt.Errorf("failed to sign client TLS cert: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDer, ca.cert.Raw},
		PrivateKey:  key,
	}, nil
}

type deviceClient struct {
	client epb.TpmEnrollzServiceClient
}

func (d *deviceClient) GetIakCert(ctx context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error) {
	return d.client.GetIakCert(ctx, req)
}

func (d *deviceClient) RotateOIakCert(ctx context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error) {
	return d.client.RotateOIakCert(ctx, req)
}

func (d *deviceClient) RotateAIKCert(ctx context.Context, opts ...grpc.CallOption) (epb.TpmEnrollzService_RotateAIKCertClient, error) {
	return d.client.RotateAIKCert(ctx, opts...)
}

func (d *deviceClient) GetControlCardVendorID(ctx context.Context, req *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error) {
	return d.client.GetControlCardVendorID(ctx, req)
}

func (d *deviceClient) Challenge(ctx context.Context, req *epb.ChallengeRequest) (*epb.ChallengeResponse, error) {
	return d.client.Challenge(ctx, req)
}

func (d *deviceClient) GetIdevidCsr(ctx context.Context, req *epb.GetIdevidCsrRequest) (*epb.GetIdevidCsrResponse, error) {
	return d.client.GetIdevidCsr(ctx, req)
}

type enrollzDeps struct {
	biz.SwitchOwnerCaClient
	biz.EnrollzDeviceClient
	biz.TpmCertVerifier
}

func main() {
	flag.Parse()

	log.Info("Initializing Enrollz Service!")

	// Build all infra-specific clients to communicate with the switch owner
	// dependency services and wire them to enrollz service biz logic library.
	//
	// For simplicity do this in main() for now - later we can add gRPC layer
	// and do this inside an RPC handler.

	// 1. Build a client to fetch switch vendor CA trust bundle.
	if *vendorCATrustBundle == "" {
		log.Exit("Flag --vendor_ca_trust_bundle must be specified")
	}
	caData, err := os.ReadFile(*vendorCATrustBundle)
	if err != nil {
		log.Exitf("Failed to read switch vendor CA trust bundle from %s: %v", *vendorCATrustBundle, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		log.Exitf("Failed to parse any certificates from switch vendor CA trust bundle at %s", *vendorCATrustBundle)
	}

	// 2. Build a client to communicate with the switch owner CA.
	if *ownerCACert == "" {
		log.Exit("Flag --owner_ca_cert must be specified")
	}
	if *ownerCAKey == "" {
		log.Exit("Flag --owner_ca_key must be specified")
	}
	if *clientIP == "" {
		log.Exit("Flag --client_ip must be specified")
	}
	ownerCaClient, err := newOwnerCA(*ownerCACert, *ownerCAKey, *clientIP)
	if err != nil {
		log.Exitf("Failed to initialize Switch Owner CA: %v", err)
	}

	// 3. Build an enrollz client to communicate with the device.
	if *port == "" {
		log.Exit("Flag --port must be specified")
	}
	addr := net.JoinHostPort(*clientIP, *port)
	clientTLSCred, err := ownerCaClient.issueClientTLSCert()
	if err != nil {
		log.Exitf("Failed to issue client TLS cert: %v", err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{clientTLSCred},
		RootCAs:            caPool,
		InsecureSkipVerify: true, //nolint:gosec // Emulator only testing
	})))
	if err != nil {
		log.Exitf("Failed to connect to device at %s: %v", addr, err)
	}
	defer conn.Close()
	devClient := &deviceClient{client: epb.NewTpmEnrollzServiceClient(conn)}

	// 4. Call enrollz biz logic module `EnrollControlCard()` for active and
	// standby control cards
	deps := &enrollzDeps{
		SwitchOwnerCaClient: ownerCaClient,
		EnrollzDeviceClient: devClient,
		TpmCertVerifier:     &TpmCertVerifierSansSerial{},
	}
	req := &biz.EnrollControlCardReq{
		ControlCardSelections: []*cpb.ControlCardSelection{
			{
				ControlCardId: &cpb.ControlCardSelection_Role{
					Role: cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
				},
			},
		},
		Deps:                 deps,
		CertVerificationOpts: x509.VerifyOptions{Roots: caPool},
		SSLProfileID:         "tls",
	}

	ctx := context.Background()
	if err := biz.EnrollControlCard(ctx, req); err != nil {
		log.Exitf("EnrollControlCard failed: %v", err)
	}
	log.Info("Successfully enrolled control cards!")
}
