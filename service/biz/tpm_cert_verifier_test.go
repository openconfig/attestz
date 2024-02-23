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

	cpb "github.com/openconfig/attestz/proto/common_definitions"
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
	certDer, err := x509.CreateCertificate(rand.Reader, certX509, certX509, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 self-signed CA cert: %v", err)
	}

	// PEM encode the cert.
	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
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
	Rsa_4096 AsymAlgo = iota
	Rsa_2048
	Rsa_1024
	Ecc_P521
	Ecc_P384
	Ecc_P256
	Ed_25519
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
	case Rsa_4096:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Rsa_2048:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Rsa_1024:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Ecc_P256:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Ecc_P384:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Ecc_P521:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case Ed_25519:
		certPubKey, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unrecognized asymmetric algo: %d", params.asymAlgo)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate asym key pair from asymmetric algo %d: %v", params.asymAlgo, err)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, cert, params.signingCert, certPubKey, params.signingPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create a signed x509 cert: %v", err)
	}
	// PEM encode the cert.
	certPem := new(bytes.Buffer)
	err = pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
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

func TestVerifyIakAndIDevIDCerts(t *testing.T) {
	// Handy to simulate IAK/IDevID cert signature validation failure.
	unknownCaCert, err := generateCaCert()
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate CA signing cert: %v", err)
	}

	cardSerial := "S0M3S3R1ALNUMB3R"
	cardID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   cardSerial,
		ControlCardSlot:     "Some card slot",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}

	tests := []struct {
		// Test description.
		desc string

		wantError bool

		cardID *cpb.ControlCardVendorId

		iakCertAsymAlgo      AsymAlgo
		iakCertSubjectSerial string
		iakCertNotBefore     time.Time
		iakCertNotAfter      time.Time

		iDevIDCertAsymAlgo      AsymAlgo
		iDevIDCertSubjectSerial string
		iDevIDCertNotBefore     time.Time
		iDevIDCertNotAfter      time.Time

		// To test against malformed PEM certs.
		customIakCertPem    string
		customIDevIDCertPem string

		// To simulate cert signature validation failure.
		customIakCaRootPem    string
		customIDevIDCaRootPem string
	}{
		{
			desc: "Success: RSA 4096 IAK and ECC P384 IDevID certs",

			wantError: false,

			cardID: cardID,

			iakCertAsymAlgo:      Rsa_4096,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Success: ECC P521 IAK and RSA 2048 IDevID certs",

			wantError: false,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P521,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 1, 0),

			iDevIDCertAsymAlgo:      Rsa_2048,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: unsupported ED25519 algo for IAK",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ed_25519,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: unsupported ED25519 algo for IDevID",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ed_25519,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: RSA key length lower than 2048 for IAK",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Rsa_1024,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: RSA key length lower than 2048 for IDevID",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Rsa_1024,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: ECC key length lower than 384 for IAK",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P256,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: ECC key length lower than 384 for IDevID",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P256,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: IAK & IDevID cert subject serials do not match expected control card serial in request",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: IAK cert and IDevID cert subject serials do not match",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: malformed PEM IAK cert",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIakCertPem: "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc: "Failure: malformed PEM IDevID cert",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIDevIDCertPem: "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc: "Failure: malformed x509 IAK cert",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIakCertPem: "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc: "Failure: malformed x509 IDevID cert",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIDevIDCertPem: "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc: "Failure: IAK cert is not yet valid",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now().AddDate(0, 0, 10),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 20),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: IDevID cert is not yet valid",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now().AddDate(1, 0, 0),
			iDevIDCertNotAfter:      time.Now().AddDate(2, 0, 0),
		},
		{
			desc: "Failure: IAK cert is expired",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now().AddDate(0, 0, -20),
			iakCertNotAfter:      time.Now().AddDate(0, 0, -10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Failure: IDevID cert is expired",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Ecc_P384,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(1, 0, 0),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now().AddDate(-2, 0, 0),
			iDevIDCertNotAfter:      time.Now().AddDate(-1, 0, 0),
		},
		{
			desc: "Failure: cannot validate IAK cert signature",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Rsa_4096,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIakCaRootPem: unknownCaCert.certPem,
		},
		{
			desc: "Failure: cannot validate IDevID cert signature",

			wantError: true,

			cardID: cardID,

			iakCertAsymAlgo:      Rsa_4096,
			iakCertSubjectSerial: cardSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 0, 10),

			iDevIDCertAsymAlgo:      Ecc_P384,
			iDevIDCertSubjectSerial: cardSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),

			customIDevIDCaRootPem: unknownCaCert.certPem,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Generate switch vendor CA IAK cert.
			genIakCaCert, err := generateCaCert()
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate IAK CA signing cert: %v", err)
			}
			// Generate switch's IAK cert signed by switch vendor CA.
			genIakCert, err := generateSignedCert(
				&CertCreationParams{
					asymAlgo:          test.iakCertAsymAlgo,
					certSubjectSerial: test.iakCertSubjectSerial,
					signingCert:       genIakCaCert.certX509,
					signingPrivKey:    genIakCaCert.privKey,
					notBefore:         test.iakCertNotBefore,
					notAfter:          test.iakCertNotAfter,
				},
			)
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate an IAK cert: %v", err)
			}

			// Generate switch vendor CA IDevID cert.
			genIDevIDCaCert, err := generateCaCert()
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate IDevID CA signing cert: %v", err)
			}
			// Generate switch's IDevID cert signed by switch vendor CA.
			genIDevIDCert, err := generateSignedCert(
				&CertCreationParams{
					asymAlgo:          test.iDevIDCertAsymAlgo,
					certSubjectSerial: test.iDevIDCertSubjectSerial,
					signingCert:       genIDevIDCaCert.certX509,
					signingPrivKey:    genIDevIDCaCert.privKey,
					notBefore:         test.iDevIDCertNotBefore,
					notAfter:          test.iDevIDCertNotAfter,
				},
			)
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate an IDevID cert: %v", err)
			}

			// Expected IAK and IDevID pub key PEMs if certs validation passes.
			wantIakPubPem := genIakCert.pubKeyPem
			wantIDevIDPubPem := genIDevIDCert.pubKeyPem

			// If a custom/malformed PEM is set, then use that.
			iakCertPemReq := genIakCert.certPem
			if test.customIakCertPem != "" {
				iakCertPemReq = test.customIakCertPem
			}
			iDevIDCertPemReq := genIDevIDCert.certPem
			if test.customIDevIDCertPem != "" {
				iDevIDCertPemReq = test.customIDevIDCertPem
			}

			// Build cert verification options.
			roots := x509.NewCertPool()
			// If a custom CA root cert PEM is set, then use that.
			iakCaCertPemReq := genIakCaCert.certPem
			if test.customIakCaRootPem != "" {
				iakCaCertPemReq = test.customIakCaRootPem
			}
			iDevIDCaCertPemReq := genIDevIDCaCert.certPem
			if test.customIDevIDCaRootPem != "" {
				iDevIDCaCertPemReq = test.customIDevIDCaRootPem
			}
			// Add resolved root CA certs to x509 cert pool.
			if !roots.AppendCertsFromPEM([]byte(iakCaCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append the following IAK CA cert to x509 cert pool: %s", iakCaCertPemReq)
			}
			if !roots.AppendCertsFromPEM([]byte(iDevIDCaCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append the following IDevID CA cert to x509 cert pool: %s", iDevIDCaCertPemReq)
			}
			certVerificationOptsReq := x509.VerifyOptions{
				Roots: roots,
			}

			// Call TpmCertVerifier's default impl of VerifyIakAndIDevIDCerts().
			req := &VerifyIakAndIDevIDCertsReq{
				controlCardID:        test.cardID,
				iakCertPem:           iakCertPemReq,
				iDevIDCertPem:        iDevIDCertPemReq,
				certVerificationOpts: certVerificationOptsReq,
			}
			gotResp, gotErr := VerifyIakAndIDevIDCerts(req)

			if test.wantError {
				// Error was expected, so do not verify the actual response.
				if gotErr == nil {
					t.Fatalf("Expected error response, but got response: %+v", gotResp)
				}
			} else {
				// No error was expected, so verify the actual response.
				if gotErr != nil {
					t.Fatalf("Expected successful response, but got error: %v", gotErr)
				}
				if diff := cmp.Diff(gotResp.iakPubPem, wantIakPubPem); diff != "" {
					t.Errorf("IAK pub PEM does not match expectations: diff = %v", diff)
				}
				if diff := cmp.Diff(gotResp.iDevIDPubPem, wantIDevIDPubPem); diff != "" {
					t.Errorf("IDevID pub PEM does not match expectations: diff = %v", diff)
				}
			}
		})
	}
}

func TestVerifyTpmCert(t *testing.T) {
	// Handy to simulate cert signature validation failure.
	unknownCaCert, err := generateCaCert()
	if err != nil {
		t.Fatalf("Test setup failed! Unable to generate CA signing cert: %v", err)
	}

	cardSerial := "S0M3S3R1ALNUMB3R"
	cardID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   cardSerial,
		ControlCardSlot:     "Some card slot",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}

	tests := []struct {
		// Test description.
		desc string

		wantError bool

		cardID *cpb.ControlCardVendorId

		certAsymAlgo      AsymAlgo
		certSubjectSerial string
		certNotBefore     time.Time
		certNotAfter      time.Time

		// To test against malformed PEM certs.
		customCertPem string

		// To simulate cert signature validation failure.
		customCaRootPem string
	}{
		{
			desc: "Success: RSA 4096 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      Rsa_4096,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Success: RSA 2048 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      Rsa_2048,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 1, 0),
		},
		{
			desc: "Success: ECC P384 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Success: ECC P521 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      Ecc_P521,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: unsupported ED25519 algo",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ed_25519,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: RSA key length lower than 2048",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Rsa_1024,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: ECC key length lower than 384",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P256,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},

		{
			desc: "Failure: malformed PEM cert",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCertPem: "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc: "Failure: malformed x509 cert",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCertPem: "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc: "Failure: cert is not yet valid",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, 10),
			certNotAfter:      time.Now().AddDate(0, 0, 20),
		},
		{
			desc: "Failure: cert is expired",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, -20),
			certNotAfter:      time.Now().AddDate(0, 0, -10),
		},
		{
			desc: "Failure: cannot validate cert signature",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Rsa_4096,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCaRootPem: unknownCaCert.certPem,
		},
		{
			desc: "Failure: Cert subject serial does not match expected control card serial in request",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      Ecc_P384,
			certSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Generate switch vendor CA cert.
			genCaCert, err := generateCaCert()
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate CA signing cert: %v", err)
			}
			// Generate switch's cert signed by switch vendor CA.
			genTpmCert, err := generateSignedCert(
				&CertCreationParams{
					asymAlgo:          test.certAsymAlgo,
					certSubjectSerial: test.certSubjectSerial,
					signingCert:       genCaCert.certX509,
					signingPrivKey:    genCaCert.privKey,
					notBefore:         test.certNotBefore,
					notAfter:          test.certNotAfter,
				},
			)
			if err != nil {
				t.Fatalf("Test setup failed! Unable to generate a TPM cert: %v", err)
			}

			// Expected cert pub key PEMs if cert validation passes.
			wantCertPubPem := genTpmCert.pubKeyPem

			// If a custom/malformed PEM is set, then use that.
			certPemReq := genTpmCert.certPem
			if test.customCertPem != "" {
				certPemReq = test.customCertPem
			}

			// Build cert verification options.
			roots := x509.NewCertPool()
			// If a custom CA root cert PEM is set, then use that.
			caCertPemReq := genCaCert.certPem
			if test.customCaRootPem != "" {
				caCertPemReq = test.customCaRootPem
			}
			// Add resolved root CA certs to x509 cert pool.
			if !roots.AppendCertsFromPEM([]byte(caCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append the following CA cert to x509 cert pool: %s", caCertPemReq)
			}
			certVerificationOptsReq := x509.VerifyOptions{
				Roots: roots,
			}

			// Call TpmCertVerifier's default impl of VerifyTpmCert().
			req := &VerifyTpmCertReq{
				controlCardID:        test.cardID,
				certPem:              certPemReq,
				certVerificationOpts: certVerificationOptsReq,
			}
			gotResp, gotErr := VerifyTpmCert(req)

			if test.wantError {
				// Error was expected, so do not verify the actual response.
				if gotErr == nil {
					t.Fatalf("Expected error response, but got response: %+v", gotResp)
				}
			} else {
				// No error was expected, so verify the actual response.
				if gotErr != nil {
					t.Fatalf("Expected successful response, but got error: %v", gotErr)
				}
				if diff := cmp.Diff(gotResp.pubPem, wantCertPubPem); diff != "" {
					t.Errorf("Cert pub PEM does not match expectations: diff = %v", diff)
				}
			}
		})
	}
}
