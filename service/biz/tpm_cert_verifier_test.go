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
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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
	eccP224Algo
	ed25519Algo
)

func parseURI(t *testing.T, rawURI string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURI)
	if err != nil {
		t.Fatalf("failed to parse URI %q: %v", rawURI, err)
	}
	return u
}

func parseURIs(t *testing.T, rawURIs ...string) []*url.URL {
	t.Helper()
	var uris []*url.URL
	for _, raw := range rawURIs {
		uris = append(uris, parseURI(t, raw))
	}
	return uris
}

type certCreationParams struct {
	asymAlgo          asymAlgo
	certSubjectSerial string
	uris              []*url.URL
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
		URIs:      params.uris,
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
	case eccP224Algo:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
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
		iakCertURIs          []*url.URL
		iakCertNotBefore     time.Time
		iakCertNotAfter      time.Time
		// iDevIDCert
		iDevIDCertAsymAlgo      asymAlgo
		iDevIDCertSubjectSerial string
		iDevIDCertURIs          []*url.URL
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
			desc:                    "Success: ECC P256 IAK and IDevID certs",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP256Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 1, 0),
			iDevIDCertAsymAlgo:      eccP256Algo,
			iDevIDCertSubjectSerial: certSerial2,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(0, 0, 10),
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
			desc:                    "Failure: ECC key length lower than 256 for IAK",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP224Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: ECC key length lower than 256 for IDevID",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP224Algo,
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
		{
			desc:                "Success: IAK and IDevID certs with serial in SAN URIs",
			wantError:           false,
			cardID:              cardID,
			iakCertAsymAlgo:     eccP384Algo,
			iakCertURIs:         parseURIs(t, "urn:serial:"+cardSerial),
			iakCertNotBefore:    time.Now(),
			iakCertNotAfter:     time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:  eccP384Algo,
			iDevIDCertURIs:      parseURIs(t, "urn:serial:"+cardSerial),
			iDevIDCertNotBefore: time.Now(),
			iDevIDCertNotAfter:  time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Success: IAK cert with SAN URI and IDevID cert with Subject serial",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertURIs:             parseURIs(t, "urn:serial:"+cardSerial),
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Success: IAK cert with ambiguous Subject serial and valid SAN URI",
			wantError:               false,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    "SN:foo SN:bar",
			iakCertURIs:             parseURIs(t, "urn:serial:"+cardSerial),
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: cannot extract serial number from IAK cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertSubjectSerial: certSerial,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:                    "Failure: cannot extract serial number from IDevID cert",
			wantError:               true,
			cardID:                  cardID,
			iakCertAsymAlgo:         eccP384Algo,
			iakCertSubjectSerial:    certSerial,
			iakCertNotBefore:        time.Now(),
			iakCertNotAfter:         time.Now().AddDate(0, 0, 10),
			iDevIDCertAsymAlgo:      eccP384Algo,
			iDevIDCertNotBefore:     time.Now(),
			iDevIDCertNotAfter:      time.Now().AddDate(1, 0, 0),
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
				uris:              test.iakCertURIs,
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
					uris:              test.iDevIDCertURIs,
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

// Simulates simplified switch vendor intermediate CA cert.
func generateInterCaCert(t *testing.T, issuerCert *x509.Certificate, issuerPrivKey any) *caCert {
	t.Helper()
	certSerial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to generate rand int for cert serial: %v", err))
	}
	certX509 := &x509.Certificate{
		SerialNumber:          certSerial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to generate a ECC P384 priv key for CA cert: %v", err))
	}

	certDer, err := x509.CreateCertificate(rand.Reader, certX509, issuerCert, &privKey.PublicKey, issuerPrivKey)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create x509 intermediate CA cert: %v", err))
	}

	// PEM encode the cert.
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})

	parsedCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to parse generated intermediate CA cert: %v", err))
	}

	return &caCert{
		certX509: parsedCert,
		certPem:  string(certPem),
		privKey:  privKey,
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
		desc               string
		wantError          bool
		certAsymAlgo       asymAlgo
		certSubjectSerial  string
		certURIs           []*url.URL
		certNotBefore      time.Time
		certNotAfter       time.Time
		useIntermediateCA  bool
		includeRootInChain bool
		// To test against malformed PEM certs.
		customCertPem string
		// To simulate cert signature validation failure.
		customCaRootPem string
	}{
		{
			desc:              "Success: RSA 4096 cert",
			wantError:         false,
			certAsymAlgo:      rsa4096Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Success: RSA 2048 cert",
			wantError:         false,
			certAsymAlgo:      rsa2048Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 1, 0),
		},
		{
			desc:              "Success: ECC P256 cert",
			wantError:         false,
			certAsymAlgo:      eccP256Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Success: ECC P384 cert",
			wantError:         false,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Success: ECC P521 cert",
			wantError:         false,
			certAsymAlgo:      eccP521Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: unsupported ED25519 algo",
			wantError:         true,
			certAsymAlgo:      ed25519Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: RSA key length lower than 2048",
			wantError:         true,
			certAsymAlgo:      rsa1024Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},
		{
			desc:              "Failure: ECC key length lower than 256",
			wantError:         true,
			certAsymAlgo:      eccP224Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
		},

		{
			desc:              "Failure: malformed PEM cert",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
			customCertPem:     "BAD HEADER\nsome payload\nBAD FOOTER\n",
		},
		{
			desc:              "Failure: malformed x509 cert",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
			customCertPem:     "-----BEGIN CERTIFICATE-----\nMIIBRTCBzaADAgECAgMAgXswCgYIKoZIzj0EAwMwADAeFw0yNTAyMTUyMTAxNTBa\n-----END CERTIFICATE-----\n",
		},
		{
			desc:              "Failure: cert is not yet valid",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, 10),
			certNotAfter:      time.Now().AddDate(0, 0, 20),
		},
		{
			desc:              "Failure: cert is expired",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now().AddDate(0, 0, -20),
			certNotAfter:      time.Now().AddDate(0, 0, -10),
		},
		{
			desc:              "Failure: cannot validate cert signature",
			wantError:         true,
			certAsymAlgo:      rsa4096Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(0, 0, 10),
			customCaRootPem:   unknownCaCert.certPem,
		},
		{
			desc:              "Success: ECC P384 cert with intermediate CA",
			wantError:         false,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: cardSerial,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
			useIntermediateCA: true,
		},
		{
			desc:               "Success: ECC P384 cert with intermediate and root CA in chain",
			wantError:          false,
			certAsymAlgo:       eccP384Algo,
			certSubjectSerial:  cardSerial,
			certNotBefore:      time.Now(),
			certNotAfter:       time.Now().AddDate(1, 0, 0),
			useIntermediateCA:  true,
			includeRootInChain: true,
		},
		{
			desc:               "Failure: Leaf to root cert chain is provided, but root does not match CA in trusted roots pool",
			wantError:          true,
			certAsymAlgo:       eccP384Algo,
			certSubjectSerial:  cardSerial,
			certNotBefore:      time.Now(),
			certNotAfter:       time.Now().AddDate(1, 0, 0),
			useIntermediateCA:  true,
			includeRootInChain: true,
			customCaRootPem:    unknownCaCert.certPem,
		},
		{
			desc:              "Failure: Cert subject serial does not match expected control card serial in request",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "AN0TH3RS3R1ALNUMB3R",
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Success: ECC P384 cert with serial in SAN URI",
			wantError:         false,
			certAsymAlgo:      eccP384Algo,
			certURIs:          parseURIs(t, "urn:serial:"+cardSerial),
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Success: ECC P384 cert with ambiguous Subject serial but valid SAN URI",
			wantError:         false,
			certAsymAlgo:      eccP384Algo,
			certSubjectSerial: "SN:foo SN:bar",
			certURIs:          parseURIs(t, "urn:serial:"+cardSerial),
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
		{
			desc:              "Failure: cannot extract serial number from cert",
			wantError:         true,
			certAsymAlgo:      eccP384Algo,
			certNotBefore:     time.Now(),
			certNotAfter:      time.Now().AddDate(1, 0, 0),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Generate switch vendor CA cert.
			genCaCert := generateCaCert(t)

			var genTpmCert *signedTpmCert
			var certPemReq string

			if test.useIntermediateCA {
				interCa := generateInterCaCert(t, genCaCert.certX509, genCaCert.privKey)
				genTpmCert = generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.certAsymAlgo,
					certSubjectSerial: test.certSubjectSerial,
					uris:              test.certURIs,
					signingCert:       interCa.certX509,
					signingPrivKey:    interCa.privKey,
					notBefore:         test.certNotBefore,
					notAfter:          test.certNotAfter,
				})
				certPemReq = genTpmCert.certPem + interCa.certPem
			} else {
				// Generate switch's cert signed by switch vendor CA.
				genTpmCert = generateSignedCert(t, &certCreationParams{
					asymAlgo:          test.certAsymAlgo,
					certSubjectSerial: test.certSubjectSerial,
					uris:              test.certURIs,
					signingCert:       genCaCert.certX509,
					signingPrivKey:    genCaCert.privKey,
					notBefore:         test.certNotBefore,
					notAfter:          test.certNotAfter,
				})
				certPemReq = genTpmCert.certPem
			}

			if test.includeRootInChain {
				certPemReq += genCaCert.certPem
			}

			// Expected cert pub key PEMs if cert validation passes.
			wantCertPubPem := genTpmCert.pubKeyPem

			// If a custom/malformed PEM is set, then use that.
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
				ControlCardID:        cardID,
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

func TestGetCertSerialNumber(t *testing.T) {
	tests := []struct {
		desc string
		cert *x509.Certificate
		want string
	}{
		{
			desc: "nil certificate",
			cert: nil,
			want: "",
		},
		{
			desc: "empty certificate",
			cert: &x509.Certificate{},
			want: "",
		},
		{
			desc: "raw serial number in Subject.SerialNumber",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "ABCD1234",
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "raw serial number with leading and trailing whitespace",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "   ABCD1234  \t\n",
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "PID and SN format in Subject.SerialNumber",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "PID:ZZ-Y-XX SN:ABCD1234",
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "SN prefix only in Subject.SerialNumber",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "SN:ABCD1234",
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "SN with whitespace in Subject.SerialNumber",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "PID:ZZ-Y-XX SN:   ABCD1234  ",
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "Subject.SerialNumber with empty serial after SN falls through to SAN URI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "PID:ZZ-Y-XX SN:",
				},
				URIs: []*url.URL{
					parseURI(t, "urn:serial:FALLBACK123"),
				},
			},
			want: "FALLBACK123",
		},
		{
			desc: "Subject.SerialNumber with whitespace-only serial after SN falls through to SAN URI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "PID:ZZ-Y-XX SN:   ",
				},
				URIs: []*url.URL{
					parseURI(t, "urn:serial:FALLBACK123"),
				},
			},
			want: "FALLBACK123",
		},
		{
			desc: "Subject.SerialNumber with whitespace only falls through to SAN URI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "   ",
				},
				URIs: []*url.URL{
					parseURI(t, "urn:serial:FALLBACK123"),
				},
			},
			want: "FALLBACK123",
		},
		{
			desc: "Subject.SerialNumber with multiple SN: is ambiguous and falls through to SAN URI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "SN:111 SN:222",
				},
				URIs: []*url.URL{
					parseURI(t, "urn:serial:SAN123"),
				},
			},
			want: "SAN123",
		},
		{
			desc: "Subject.SerialNumber with multiple SN: and no SAN URI returns empty",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "SN:111 SN:222",
				},
			},
			want: "",
		},
		{
			desc: "Subject.SerialNumber with whitespace only and no SAN URI returns empty",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "    ",
				},
			},
			want: "",
		},
		{
			desc: "SAN URI urn:serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "urn:serial:ABCD1234"),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "SAN URI case-insensitive scheme and prefix",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "URN:SERIAL:ABCD1234"),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "SAN URI mixed-case prefix",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "Urn:Serial:ABCD1234"),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "SAN URI with whitespace around serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "urn:serial:  ABCD1234  "),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "Subject.SerialNumber takes precedence over SAN URI",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					SerialNumber: "SUBJ1234",
				},
				URIs: []*url.URL{
					parseURI(t, "urn:serial:SAN5678"),
				},
			},
			want: "SUBJ1234",
		},
		{
			desc: "Multiple URIs with non-serial URI followed by urn:serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "https://example.com/cert"),
					parseURI(t, "urn:other:1234"),
					parseURI(t, "urn:serial:ABCD1234"),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "Multiple URIs with nil URI followed by urn:serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					nil,
					parseURI(t, "urn:serial:ABCD1234"),
				},
			},
			want: "ABCD1234",
		},
		{
			desc: "Multiple urn:serial URIs returns first matching",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "urn:serial:FIRST"),
					parseURI(t, "urn:serial:SECOND"),
				},
			},
			want: "FIRST",
		},
		{
			desc: "SAN URI with empty serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "urn:serial:"),
				},
			},
			want: "",
		},
		{
			desc: "SAN URI with whitespace-only serial",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "urn:serial:   "),
				},
			},
			want: "",
		},
		{
			desc: "SAN URIs with no urn:serial prefix",
			cert: &x509.Certificate{
				URIs: []*url.URL{
					parseURI(t, "https://example.com/device/1234"),
					parseURI(t, "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
				},
			},
			want: "",
		},
		{
			desc: "SAN URIs containing only nil",
			cert: &x509.Certificate{
				URIs: []*url.URL{nil},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := getCertSerialNumber(tc.cert)
			if got != tc.want {
				t.Errorf("getCertSerialNumber(%v) = %q, want %q", tc.cert, got, tc.want)
			}
		})
	}
}

