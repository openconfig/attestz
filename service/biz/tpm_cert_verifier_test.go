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

package biz

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type CaCert struct {
	certX509 *x509.Certificate
	certPem  string
	privKey  any
}

// Simulates simplified switch vendor CA cert.
func generateCaCert() (*CaCert, error) {
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate rand int for cert serial: %v", err)
	}
	certX509 := &x509.Certificate{
		SerialNumber:          certSerial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a ECC P384 priv key for CA cert: %v", err)
	}

	// CA cert is self-signed, so pass caCert twice.
	certBytes, err := x509.CreateCertificate(rand.Reader, certX509, certX509, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 self-signed CA cert: %v", err)
	}

	// PEM encode the cert.
	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode DER cert to PEM: %v", err)
	}

	return &CaCert{
		certX509: certX509,
		certPem:  certPem.String(),
		privKey:  privKey,
	}, nil
}

type SignedTpmCert struct {
	certPem   string
	pubKeyPem string
}

type AsymAlgo int

const (
	RSA_4096 AsymAlgo = iota
	RSA_2048
	RSA_1024
	ECC_P384
	ECC_P256
	ED_25519
)

type CertCreationParams struct {
	asymAlgo          AsymAlgo
	certSubjectSerial string
	signingCert       *x509.Certificate
	signingPrivKey    any
	notBefore         time.Time
	notAfter          time.Time
}

// Simulates simplified switch's IAK or IDevID certs.
func generateSignedCert(params *CertCreationParams) (*SignedTpmCert, error) {
	// Cert serial (different form cert *subject* serial number).
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate rand int for cert serial: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: certSerial,
		Subject: pkix.Name{
			SerialNumber: params.certSubjectSerial,
		},
		NotBefore: params.notBefore,
		NotAfter:  params.notAfter,
	}

	var certPubKey any
	switch params.asymAlgo {
	case RSA_4096:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case RSA_2048:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case RSA_1024:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case ECC_P256:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case ECC_P384:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case ED_25519:
		certPubKey, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unrecognized asymmetric algo: %d", params.asymAlgo)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate asym key pair from asymmetric algo %d: %v", params.asymAlgo, err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, params.signingCert, certPubKey, params.signingPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create a signed x509 cert: %v", err)
	}
	// PEM encode the cert.
	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode DER cert to PEM: %v", err)
	}

	// Marshal pub key to DER.
	derPub, err := x509.MarshalPKIXPublicKey(certPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pub key to DER: %v", err)
	}
	// Convert DER pub key to PEM.
	pubKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPub,
	}
	pubKeyPem := new(bytes.Buffer)
	if err = pem.Encode(pubKeyPem, pubKeyBlock); err != nil {
		return nil, fmt.Errorf("failed to encode pub key DER to PEM: %v", err)
	}

	return &SignedTpmCert{
		certPem:   certPem.String(),
		pubKeyPem: pubKeyPem.String(),
	}, nil
}

func TestVerifyAndParseIakAndIDevIdCerts(t *testing.T) {
	/*
		TODO(jenia-grunin):
		* Tests to add:
			- Unsupported algo such as ED25519.
			- Bad pub key length for RSA.
			- Bad pub key length for ECC.
			- IAK and IDevID cert serials don't match.
			- Bad cert pem header.
			- Good pem cert header, but bad x509 structure.
			- Repeat above for both IAK and IDevID certs.
	*/

	iakCaCert, err := generateCaCert()
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate IAK CA signing cert: %v", err)
	}

	iakCert, err := generateSignedCert(
		&CertCreationParams{
			asymAlgo:          RSA_4096,
			certSubjectSerial: "S0M3S3R1ALNUMB3R",
			signingCert:       iakCaCert.certX509,
			signingPrivKey:    iakCaCert.privKey,
			notBefore:         time.Now(),
			notAfter:          time.Now().AddDate(0, 0, 10),
		},
	)
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate an IAK cert: %v", err)
	}

	iDevIdCaCert, err := generateCaCert()
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate IDevID CA signing cert: %v", err)
	}

	iDevIdCert, err := generateSignedCert(
		&CertCreationParams{
			asymAlgo:          ECC_P384,
			certSubjectSerial: "S0M3S3R1ALNUMB3R",
			signingCert:       iDevIdCaCert.certX509,
			signingPrivKey:    iDevIdCaCert.privKey,
			notBefore:         time.Now(),
			notAfter:          time.Now().AddDate(0, 0, 10),
		},
	)
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate an IDevID cert: %v", err)
	}

	iakCertPemRsa2048 := iakCert.certPem
	wantIakPubPem := iakCert.pubKeyPem

	iDevIdCertPemEcc384 := iDevIdCert.certPem
	wantIDevIdPubPem := iDevIdCert.pubKeyPem

	req := &TpmCertVerifierReq{
		iakCertPem:    iakCertPemRsa2048,
		iDevIdCertPem: iDevIdCertPemEcc384,
	}
	resp, err := VerifyAndParseIakAndIDevIdCerts(req)

	if err != nil {
		t.Fatalf("Unexpected error response %v", err)
	}

	if diff := cmp.Diff(resp.iakPubPem, wantIakPubPem); diff != "" {
		t.Errorf("IAK pub PEM does not match expectations: diff = %v", diff)
	}
	if diff := cmp.Diff(resp.iDevIdPubPem, wantIDevIdPubPem); diff != "" {
		t.Errorf("IDevID pub PEM does not match expectations: diff = %v", diff)
	}
}
