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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal CA private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestGenerateClientCert(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)

	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca_cert.pem")
	caKeyPath := filepath.Join(dir, "ca_key.pem")
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		t.Fatalf("failed to write CA cert file: %v", err)
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write CA key file: %v", err)
	}

	tlsCert, err := generateClientCert(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("generateClientCert() failed: %v", err)
	}

	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("got %d certificates, want 1", len(tlsCert.Certificate))
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("got nil PrivateKey in tls.Certificate")
	}

	clientCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated client certificate: %v", err)
	}

	if clientCert.Subject.CommonName != "attestz-client" {
		t.Errorf("CommonName = %q, want %q", clientCert.Subject.CommonName, "attestz-client")
	}

	hasClientAuth := false
	for _, usage := range clientCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		t.Errorf("ExtKeyUsage does not contain ExtKeyUsageClientAuth: %v", clientCert.ExtKeyUsage)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := clientCert.Verify(opts); err != nil {
		t.Errorf("clientCert.Verify() failed: %v", err)
	}
}

func TestGenerateClientCertErrors(t *testing.T) {
	caCertPEM, caKeyPEM := generateTestCA(t)

	dir := t.TempDir()
	validCertPath := filepath.Join(dir, "valid_cert.pem")
	validKeyPath := filepath.Join(dir, "valid_key.pem")
	invalidCertPath := filepath.Join(dir, "invalid_cert.pem")
	invalidKeyPath := filepath.Join(dir, "invalid_key.pem")

	if err := os.WriteFile(validCertPath, caCertPEM, 0644); err != nil {
		t.Fatalf("failed to write valid cert: %v", err)
	}
	if err := os.WriteFile(validKeyPath, caKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write valid key: %v", err)
	}
	if err := os.WriteFile(invalidCertPath, []byte("invalid pem"), 0644); err != nil {
		t.Fatalf("failed to write invalid cert: %v", err)
	}
	if err := os.WriteFile(invalidKeyPath, []byte("invalid pem"), 0600); err != nil {
		t.Fatalf("failed to write invalid key: %v", err)
	}

	// Missing files.
	if _, err := generateClientCert(filepath.Join(dir, "nonexistent.pem"), validKeyPath); err == nil {
		t.Error("generateClientCert with nonexistent cert file succeeded, want error")
	}
	if _, err := generateClientCert(validCertPath, filepath.Join(dir, "nonexistent.pem")); err == nil {
		t.Error("generateClientCert with nonexistent key file succeeded, want error")
	}

	// Invalid PEM content.
	if _, err := generateClientCert(invalidCertPath, validKeyPath); err == nil {
		t.Error("generateClientCert with invalid cert PEM succeeded, want error")
	}
	if _, err := generateClientCert(validCertPath, invalidKeyPath); err == nil {
		t.Error("generateClientCert with invalid key PEM succeeded, want error")
	}
}
