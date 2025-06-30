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
	"context"
	"crypto"
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
	"google.golang.org/protobuf/testing/protocmp"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

type caCert struct {
	certX509 *x509.Certificate
	certPem  string
	privKey  any
}

// Simulates simplified switch vendor CA cert.
func generateCaCert(t *testing.T) *caCert {
	t.Helper()
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to generate rand int for cert serial: %v", err))
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
		t.Fatal(fmt.Errorf("failed to generate a ECC P384 priv key for CA cert: %v", err))
	}

	// CA cert is self-signed, so pass caCert twice.
	certDer, err := x509.CreateCertificate(rand.Reader, certX509, certX509, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create x509 self-signed CA cert: %v", err))
	}

	// PEM encode the cert.
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	return &caCert{
		certX509: certX509,
		certPem:  string(certPem),
		privKey:  privKey,
	}
}

type signedTpmCert struct {
	certPem   string
	pubKeyPem string
}

type asymAlgo int

const (
	rsa4096Algo asymAlgo = iota
	rsa2048Algo
	rsa1024Algo
	eccP521Algo
	eccP384Algo
	eccP256Algo
	ed25519Algo
)

type certCreationParams struct {
	asymAlgo          asymAlgo
	certSubjectSerial string
	signingCert       *x509.Certificate
	signingPrivKey    any
	notBefore         time.Time
	notAfter          time.Time
}

// Simulates simplified switch's IAK or IDevID certs.
func generateSignedCert(t *testing.T, params *certCreationParams) *signedTpmCert {
	t.Helper()
	// Cert serial (different form cert *subject* serial number).
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to generate rand int for cert serial: %v", err))
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
	case rsa4096Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case rsa2048Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case rsa1024Algo:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP256Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP384Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case eccP521Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err == nil {
			certPubKey = &certPrivKey.PublicKey
		}
	case ed25519Algo:
		certPubKey, _, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatal(fmt.Errorf("unrecognized asymmetric algo: %d", params.asymAlgo))
	}
	if err != nil {
		t.Fatal(fmt.Errorf("failed to generate asym key pair from asymmetric algo %d: %v", params.asymAlgo, err))
	}

	certDer, err := x509.CreateCertificate(rand.Reader, cert, params.signingCert, certPubKey, params.signingPrivKey)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create a signed x509 cert: %v", err))
	}
	// PEM encode the cert.
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	// Marshal pub key to DER.
	derPub, err := x509.MarshalPKIXPublicKey(certPubKey)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to marshal pub key to DER: %v", err))
	}
	// Convert DER pub key to PEM.
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derPub,
		})

	return &signedTpmCert{
		certPem:   string(certPem),
		pubKeyPem: string(pubKeyPem),
	}
}

func TestVerifyIakAndIDevIDCerts(t *testing.T) {
	// Handy to simulate IAK/IDevID cert signature validation failure.
	unknownCaCert := generateCaCert(t)

	cardSerial := "ABCD1234"
	cardID := &cpb.ControlCardVendorId{
		ControlCardRole:     cpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ControlCardSerial:   cardSerial,
		ControlCardSlot:     "Some card slot",
		ChassisManufacturer: "Some manufacturer",
		ChassisPartNumber:   "Some part",
		ChassisSerialNumber: "Some chassis serial",
	}
	certSerial := "PID:ZZ-Y-XX SN:ABCD1234"
	certSerial2 := "ABCD1234"

	tests := []struct {
		// Test description.
		desc      string
		wantError bool
		cardID    *cpb.ControlCardVendorId
		// iakCert
		iakCertAsymAlgo      asymAlgo
		iakCertSubjectSerial string
		iakCertNotBefore     time.Time
		iakCertNotAfter      time.Time
		// iDevIDCert
		iDevIDCertAsymAlgo      asymAlgo
		iDevIDCertSubjectSerial string
		iDevIDCertNotBefore     time.Time
		iDevIDCertNotAfter      time.Time
		// To test against malformed PEM certs.
		customIakCertPem    string
		customIDevIDCertPem string
		// To simulate cert signature validation failure.
		customIakCaRootPem    string
		customIDevIDCaRootPem string
		// To simulate a verifying iak for a secondary control card for which IDevID is optional.
		noIDevID bool
	}{
		{
			desc:                    "Success: RSA 4096 IAK and ECC P384 IDevID certs",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Success: ECC P521 IAK and RSA 2048 IDevID certs",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP521Algo,
			iakCertSubjectSerial:    certSerial2,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 1, 0),
			iDevIDCertAsymAlgo:      rsa2048Algo,
			iDevIDCertSubjectSerial: certSerial2,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                 "Success: ECC P521 IAK and no IDevID cert",
			wantError:            false,
			cardID:               cardID,
			iakCertAsymAlgo:      eccP521Algo,
			iakCertSubjectSerial: certSerial,
			iakCertNotBefore:     time.Now(),
			iakCertNotAfter:      time.Now().AddDate(0, 1, 0),
			noIDevID:             true,
		},
		{
			desc:                    "Failure: unsupported ED25519 algo for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         ed25519Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                    "Failure: unsupported ED25519 algo for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      ed25519Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:                    "Failure: RSA key length lower than 2048 for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa1024Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: RSA key length lower than 2048 for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      rsa1024Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: ECC key length lower than 384 for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP256Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: ECC key length lower than 384 for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP256Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: IAK & IDevID cert subject serials do not match expected control card serial in request",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "AN0TH3RS3R1ALNUMB3R",
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: IAK cert and IDevID cert subject serials do not match",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: malformed PEM IAK cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIakCertPem:        "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:                    "Failure: malformed PEM IDevID cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIDevIDCertPem:     "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:                    "Failure: malformed x509 IAK cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIakCertPem:        "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc:                    "Failure: malformed x509 IDevID cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIDevIDCertPem:     "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc:                    "Failure: IAK cert is not yet valid",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now().AddDate(0, 0, 10),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 20),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: IDevID cert is not yet valid",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now().AddDate(1, 0, 0),
			iDevIDCertNotAfter:      time.Now().AddDate(2, 0, 0),
		},
		{
			desc:                    "Failure: IAK cert is expired",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now().AddDate(0, 0, -20),
			iakCertNotAfter:         time.Now().AddDate(0, 0, -10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: IDevID cert is expired",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(1, 0, 0),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now().AddDate(-2, 0, 0),
			iDevIDCertNotAfter:      time.Now().AddDate(-1, 0, 0),
		},
		{
			desc:                    "Failure: cannot validate IAK cert signature",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIakCaRootPem:      unknownCaCert.certPem,
		},
		{
			desc:                    "Failure: cannot validate IDevID cert signature",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         rsa4096Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
			customIDevIDCaRootPem:   unknownCaCert.certPem,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Generate switch vendor CA IAK cert.
			genIakCaCert := generateCaCert(t)

			// Generate switch's IAK cert signed by switch vendor CA.
			genIakCert := generateSignedCert(t, &certCreationParams{
				asymAlgo:          test.iakCertAsymAlgo,
				certSubjectSerial: test.iakCertSubjectSerial,
				signingCert:       genIakCaCert.certX509,
				signingPrivKey:    genIakCaCert.privKey,
				notBefore:         test.iakCertNotBefore,
				notAfter:          test.iakCertNotAfter,
			})

			// Expected IAK pub key PEM if cert validation passes.
			wantIakPubPem := genIakCert.pubKeyPem

			// If a custom/malformed PEM is set, then use that.
			iakCertPemReq := genIakCert.certPem
			if test.customIakCertPem != "" {
				iakCertPemReq = test.customIakCertPem
			}
			// If a custom CA root cert PEM is set, then use that.
			iakCaCertPemReq := genIakCaCert.certPem
			if test.customIakCaRootPem != "" {
				iakCaCertPemReq = test.customIakCaRootPem
			}

			// Build cert verification options.
			roots := x509.NewCertPool()
			// Add resolved root CA certs to x509 cert pool.
			if !roots.AppendCertsFromPEM([]byte(iakCaCertPemReq)) {
				t.Fatalf("Test setup failed! Unable to append the following IAK CA cert to x509 cert pool: %s", iakCaCertPemReq)
			}

			wantIDevIDPubPem := ""
			iDevIDCertPemReq := ""
			if !test.noIDevID {
				// Generate switch vendor CA IDevID cert.
				genIDevIDCaCert := generateCaCert(t)

				// Generate switch's IDevID cert signed by switch vendor CA.
				genIDevIDCert := generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.iDevIDCertAsymAlgo,
					certSubjectSerial: test.iDevIDCertSubjectSerial,
					signingCert:       genIDevIDCaCert.certX509,
					signingPrivKey:    genIDevIDCaCert.privKey,
					notBefore:         test.iDevIDCertNotBefore,
					notAfter:          test.iDevIDCertNotAfter,
				})

				// Expected IDevID pub key PEM if cert validation passes.
				wantIDevIDPubPem = genIDevIDCert.pubKeyPem

				// If a custom/malformed PEM is set, then use that.
				iDevIDCertPemReq = genIDevIDCert.certPem
				if test.customIDevIDCertPem != "" {
					iDevIDCertPemReq = test.customIDevIDCertPem
				}

				// If a custom CA root cert PEM is set, then use that.
				iDevIDCaCertPemReq := genIDevIDCaCert.certPem
				if test.customIDevIDCaRootPem != "" {
					iDevIDCaCertPemReq = test.customIDevIDCaRootPem
				}

				if !roots.AppendCertsFromPEM([]byte(iDevIDCaCertPemReq)) {
					t.Fatalf("Test setup failed! Unable to append the following IDevID CA cert to x509 cert pool: %s", iDevIDCaCertPemReq)
				}
			}

			certVerificationOptsReq := x509.VerifyOptions{
				Roots: roots,
			}

			// Call TpmCertVerifier's default impl of VerifyIakAndIDevIDCerts().
			req := &VerifyIakAndIDevIDCertsReq{
				ControlCardID:        test.cardID,
				IakCertPem:           iakCertPemReq,
				IDevIDCertPem:        iDevIDCertPemReq,
				CertVerificationOpts: certVerificationOptsReq,
			}
			ctx := context.Background()
			defTpmCertVerifier := DefaultTpmCertVerifier{}
			gotResp, gotErr := defTpmCertVerifier.VerifyIakAndIDevIDCerts(ctx, req)

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
				if diff := cmp.Diff(gotResp.IakPubPem, wantIakPubPem); diff != "" {
					t.Errorf("IAK pub PEM does not match expectations: diff = %v", diff)
				}
				if diff := cmp.Diff(gotResp.IDevIDPubPem, wantIDevIDPubPem); diff != "" {
					t.Errorf("IDevID pub PEM does not match expectations: diff = %v", diff)
				}
			}
		})
	}
}

func TestVerifyTpmCert(t *testing.T) {
	// Handy to simulate cert signature validation failure.
	unknownCaCert := generateCaCert(t)

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

		certAsymAlgo      asymAlgo
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

			certAsymAlgo:      rsa4096Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Success: RSA 2048 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      rsa2048Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 1, 0),
		},
		{
			desc: "Success: ECC P384 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc: "Success: ECC P521 cert",

			wantError: false,

			cardID: cardID,

			certAsymAlgo:      eccP521Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: unsupported ED25519 algo",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      ed25519Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: RSA key length lower than 2048",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      rsa1024Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc: "Failure: ECC key length lower than 384",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP256Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},

		{
			desc: "Failure: malformed PEM cert",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCertPem: "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc: "Failure: malformed x509 cert",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCertPem: "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc: "Failure: cert is not yet valid",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, 10),
			certNotAfter:      time.Now().AddDate(0, 0, 20),
		},
		{
			desc: "Failure: cert is expired",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, -20),
			certNotAfter:      time.Now().AddDate(0, 0, -10),
		},
		{
			desc: "Failure: cannot validate cert signature",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      rsa4096Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),

			customCaRootPem: unknownCaCert.certPem,
		},
		{
			desc: "Failure: Cert subject serial does not match expected control card serial in request",

			wantError: true,

			cardID: cardID,

			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Generate switch vendor CA cert.
			genCaCert := generateCaCert(t)

			// Generate switch's cert signed by switch vendor CA.
			genTpmCert := generateSignedCert(t, &certCreationParams{
				asymAlgo:          test.certAsymAlgo,
				certSubjectSerial: test.certSubjectSerial,
				signingCert:       genCaCert.certX509,
				signingPrivKey:    genCaCert.privKey,
				notBefore:         test.certNotBefore,
				notAfter:          test.certNotAfter,
			})

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
				ControlCardID:        test.cardID,
				CertPem:              certPemReq,
				CertVerificationOpts: certVerificationOptsReq,
			}
			ctx := context.Background()
			defTpmCertVerifier := DefaultTpmCertVerifier{}
			gotResp, gotErr := defTpmCertVerifier.VerifyTpmCert(ctx, req)

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
				if diff := cmp.Diff(gotResp.PubPem, wantCertPubPem); diff != "" {
					t.Errorf("Cert pub PEM does not match expectations: diff = %v", diff)
				}
			}
		})
	}
}

func generateRSAKeyPair(t *testing.T, keySize int) (*rsa.PrivateKey, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA public key: %v", err)
	}
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})
	return privKey, string(pubKeyPem)
}

func generateECDSAKeyPair(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal ECDSA public key: %v", err)
	}
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})
	return privKey, string(pubKeyPem)
}

func signRSA(t *testing.T, privKey *rsa.PrivateKey, nonce []byte, hash crypto.Hash) []byte {
	t.Helper()
	hashed := hash.New()
	hashed.Write(nonce)
	signature, err := rsa.SignPSS(rand.Reader, privKey, hash, hashed.Sum(nil), nil)
	if err != nil {
		t.Fatalf("Failed to sign RSA: %v", err)
	}
	return signature
}

func signECDSA(t *testing.T, privKey *ecdsa.PrivateKey, nonce []byte, hash crypto.Hash) []byte {
	t.Helper()
	hashed := hash.New()
	hashed.Write(nonce)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hashed.Sum(nil))
	if err != nil {
		t.Fatalf("Failed to sign ECDSA: %v", err)
	}
	return signature
}
func TestVerifyNonceSignature(t *testing.T) {
	ctx := context.Background()
	tpmCertVerifier := &DefaultTpmCertVerifier{}

	// Generate RSA key pair
	rsaPrivKey, rsaPubKeyPem := generateRSAKeyPair(t, 3072)
	// Generate ECDSA key pair
	ecdsaPrivKey, ecdsaPubKeyPem := generateECDSAKeyPair(t, elliptic.P384())
	ecdsaP256PrivKey, ecdsaP256PubKeyPem := generateECDSAKeyPair(t, elliptic.P256())

	// Generate Nonce
	nonce := []byte("test-nonce")

	// Generate valid signatures
	rsaSHA256Sig := signRSA(t, rsaPrivKey, nonce, crypto.SHA256)
	ecdsaSHA384Sig := signECDSA(t, ecdsaPrivKey, nonce, crypto.SHA384)
	ecdsaSHA256Sig := signECDSA(t, ecdsaP256PrivKey, nonce, crypto.SHA256)
	ecdsaSHA512Sig := signECDSA(t, ecdsaPrivKey, nonce, crypto.SHA512)

	// Generate invalid signature
	invalidSig := []byte("invalid-signature")

	tests := []struct {
		name     string
		req      *VerifyNonceSignatureReq
		wantResp *VerifyNonceSignatureResp
		wantErr  bool
	}{
		{
			name: "Valid RSA SHA256 Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: rsaPubKeyPem,
				Signature: rsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: &VerifyNonceSignatureResp{IsValid: true},
			wantErr:  false,
		},
		{
			name: "Valid ECDSA SHA384 Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: ecdsaPubKeyPem,
				Signature: ecdsaSHA384Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA384,
			},
			wantResp: &VerifyNonceSignatureResp{IsValid: true},
			wantErr:  false,
		},
		{
			name: "Valid ECDSA SHA256 Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: ecdsaP256PubKeyPem,
				Signature: ecdsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: &VerifyNonceSignatureResp{IsValid: true},
			wantErr:  false,
		},
		{
			name: "Valid ECDSA SHA512 Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: ecdsaPubKeyPem,
				Signature: ecdsaSHA512Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA512,
			},
			wantResp: &VerifyNonceSignatureResp{IsValid: true},
			wantErr:  false,
		},
		{
			name: "Invalid Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: rsaPubKeyPem,
				Signature: invalidSig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: &VerifyNonceSignatureResp{IsValid: false},
			wantErr:  false,
		},
		{
			name: "Invalid Hash Algorithm",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: rsaPubKeyPem,
				Signature: rsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_UNSPECIFIED,
			},
			wantResp: nil,
			wantErr:  true,
		},
		{
			name: "Invalid IAK Public Key (Malformed PEM)",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: "invalid-pem",
				Signature: rsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: nil,
			wantErr:  true,
		},
		{
			name: "Invalid IAK Public Key (Unsupported Key Type)",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: string(pem.EncodeToMemory(&pem.Block{Type: "INVALID KEY", Bytes: []byte("invalid-key")})),
				Signature: rsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: nil,
			wantErr:  true,
		},
		{
			name:     "Nil Request",
			req:      nil,
			wantResp: nil,
			wantErr:  true,
		},
		{
			name: "Empty IAKPubPem",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: "",
				Signature: rsaSHA256Sig,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: nil,
			wantErr:  true,
		},
		{
			name: "Nil Signature",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: rsaPubKeyPem,
				Signature: nil,
				Nonce:     nonce,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: nil,
			wantErr:  true,
		},
		{
			name: "Nil Nonce",
			req: &VerifyNonceSignatureReq{
				IAKPubPem: rsaPubKeyPem,
				Signature: rsaSHA256Sig,
				Nonce:     nil,
				HashAlgo:  cpb.Tpm20HashAlgo_TPM20HASH_ALGO_SHA256,
			},
			wantResp: nil,
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotResp, err := tpmCertVerifier.VerifyNonceSignature(ctx, tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyNonceSignature(%v) error = %v, wantErr %v", tc.req, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.wantResp, gotResp, protocmp.Transform()); diff != "" {
				t.Errorf("VerifyNonceSignature(%v) returned an unexpected diff (-want +got): %v", tc.req, diff)
			}
		})
	}
}
