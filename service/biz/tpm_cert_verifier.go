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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-cmp/cmp"

	log "github.com/golang/glog"
)

// Request to VerifyAndParseIakAndIDevIdCerts().
type TpmCertVerifierReq struct {
	// Verification options for IAK and IDevID certs.
	certVerificationOpts x509.VerifyOptions
	// PEM-encoded IAK x509 attestation cert.
	iakCertPem string
	// PEM-encoded IDevID x509 TLS cert.
	iDevIdCertPem string
}

// Response from VerifyAndParseIakAndIDevIdCerts().
type TpmCertVerifierResp struct {
	// PEM-encoded IAK public key.
	iakPubPem string
	// PEM-encoded IDevID public key.
	iDevIdPubPem string
}

// Parses and verifies IAK and IDevID certs.
type TpmCertVerifier interface {
	// Performs the following:
	// 1. Validate IDevID TLS cert.
	// 2. Validate IAK cert.
	// 3. Make sure IAK and IDevID serials match.
	// 4. Parse IAK pub from IAK cert and validate it (accepted crypto algo and key length).
	// 5. Parse IDevID pub from IDevID cert and validate it (accepted crypto algo and key length).
	VerifyAndParseIakAndIDevIdCerts(req *TpmCertVerifierReq) (*TpmCertVerifierResp, error)
}

// Default/reference implementation of TpmCertVerifier.VerifyAndParseIakAndIDevIdCerts()
func VerifyAndParseIakAndIDevIdCerts(req *TpmCertVerifierReq) (*TpmCertVerifierResp, error) {
	iakX509, err := VerifyAndParsePemCert(req.iakCertPem, req.certVerificationOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and parse IAK cert: %v", err)
	}
	log.Info("Successfully verified and parsed IAK cert")

	iDevIdX509, err := VerifyAndParsePemCert(req.iDevIdCertPem, req.certVerificationOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and parse IDevID cert: %v", err)
	}
	log.Info("Successfully verified and parsed IDevID cert")

	// Verify IAK and IDevID cert subject serials match.
	if diff := cmp.Diff(iakX509.Subject.SerialNumber, iDevIdX509.Subject.SerialNumber); diff != "" {
		return nil, fmt.Errorf("subject serial numbers of IAK and IDevID certs do not match: diff = %v", diff)
	}
	log.Infof("Subject serial numbers of IAK and IDevID certs match: %s", iakX509.Subject.SerialNumber)

	// Verify and convert IAK and IDevID certs' pub keys to PEM.
	iakPubPem, err := VerifyAndSerializePubKey(iakX509)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and serialize IAK pub key: %v", err)
	}
	log.Infof("Successfully verified and parsed IAK pub key PEM %s", iakPubPem)

	iDevIdPubPem, err := VerifyAndSerializePubKey(iDevIdX509)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and serialize IDevID pub key: %v", err)
	}
	log.Infof("Successfully verified and parsed IDevID pub key PEM %s", iDevIdPubPem)

	return &TpmCertVerifierResp{
		iakPubPem:    iakPubPem,
		iDevIdPubPem: iDevIdPubPem,
	}, nil
}

// Parses PEM (IAK or IDevID) cert, verifies it and returns the parsed x509 structure.
func VerifyAndParsePemCert(certPem string, certVerificationOpts x509.VerifyOptions) (*x509.Certificate, error) {
	// Convert PEM to DER.
	certDer, _ := pem.Decode([]byte(certPem))
	if certDer == nil {
		return nil, fmt.Errorf("failed to decode cert PEM into DER cert_pem=%s",
			certPem)
	}
	// Parse DER cert into structured x509 object.
	x509CertParsed, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert DER into x509 structure cert_pem=%s: %v",
			certPem, err)
	}

	// Validate cert expiration and verify signature using provided options.
	if _, err := x509CertParsed.Verify(certVerificationOpts); err != nil {
		return nil, fmt.Errorf("failed to verify certificate_pem=%s: %v",
			certPem, err)
	}

	return x509CertParsed, nil
}

// Fetches (IAK or IDevID) public key from x509 cert, validates the key and returns it in the PEM format.
func VerifyAndSerializePubKey(cert *x509.Certificate) (string, error) {
	// Verify the underlying pub key is ECC P384 (or higher) or RSA 2048 (or higher).
	switch certPubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubKeyLen := certPubKey.Size() * 8
		if pubKeyLen < 2048 {
			return "", fmt.Errorf("pub RSA key must be 2048 bits or higher, but was %d", pubKeyLen)
		}
		log.Infof("pub key algorithm is %s %d", cert.PublicKeyAlgorithm, pubKeyLen)
	case *ecdsa.PublicKey:
		pubKeyLen := certPubKey.Curve.Params().BitSize
		if pubKeyLen < 384 {
			return "", fmt.Errorf("pub ECC key must be 384 bits or higher, but was %d", pubKeyLen)
		}
		log.Infof("pub key algorithm is %s %d", cert.PublicKeyAlgorithm, pubKeyLen)
	default:
		return "", fmt.Errorf("unsupported public key algorithm: %s", cert.PublicKeyAlgorithm)
	}

	// Marshal pub key to DER.
	derPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal cert public key to DER: %v", err)
	}

	// Convert DER pub key to PEM and return it.
	pubKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPub,
	}
	pubKeyPem := new(bytes.Buffer)
	if err = pem.Encode(pubKeyPem, pubKeyBlock); err != nil {
		return "", fmt.Errorf("failed to encode DER pub key to PEM: %v", err)
	}

	return pubKeyPem.String(), nil
}
