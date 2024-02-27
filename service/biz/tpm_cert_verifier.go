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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-cmp/cmp"

	log "github.com/golang/glog"
	cpb "github.com/openconfig/attestz/proto/common_definitions"
)

// VerifyIakAndIDevIDCertsReq is the request to VerifyIakAndIDevIDCerts().
type VerifyIakAndIDevIDCertsReq struct {
	// Identity fields of a given switch control card.
	ControlCardID *cpb.ControlCardVendorId
	// Verification options for IAK and IDevID certs.
	CertVerificationOpts x509.VerifyOptions
	// PEM-encoded IAK x509 attestation cert.
	IakCertPem string
	// PEM-encoded IDevID x509 TLS cert.
	IDevIDCertPem string
}

// VerifyIakAndIDevIDCertsResp is the response from VerifyIakAndIDevIDCerts().
type VerifyIakAndIDevIDCertsResp struct {
	// PEM-encoded IAK public key.
	IakPubPem string
	// PEM-encoded IDevID public key.
	IDevIDPubPem string
}

// VerifyTpmCertReq is the request to VerifyTpmCert().
type VerifyTpmCertReq struct {
	// Identity fields of a given switch control card.
	ControlCardID *cpb.ControlCardVendorId
	// Verification options for a TPM-based cert such as IAK or IDevID.
	CertVerificationOpts x509.VerifyOptions
	// PEM-encoded x509 attestation IAK or TLS IDevID cert.
	CertPem string
}

// VerifyTpmCertResp is the response from VerifyTpmCert().
type VerifyTpmCertResp struct {
	// PEM-encoded public key from x509 attestation IAK or TLS IDevID cert.
	PubPem string
}

// TpmCertVerifier parses and verifies IAK and IDevID certs.
type TpmCertVerifier interface {
	// Performs the following:
	// 1. Validate (signature and expiration) IDevID TLS cert.
	// 2. Validate (signature and expiration) IAK cert.
	// 3. Make sure IAK and IDevID cert subject serials match.
	// 4. Parse IAK pub from IAK cert and validate it (accepted crypto algo and key length).
	// 5. Parse IDevID pub from IDevID cert and validate it (accepted crypto algo and key length).
	VerifyIakAndIDevIDCerts(req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error)

	// Performs the following:
	// 1. Validate (signature and expiration) a TPM-based cert such as IAK or IDevID.
	// 2. Parse pub key from the cert and validate it (accepted crypto algo and key length).
	VerifyTpmCert(req *VerifyTpmCertReq) (*VerifyTpmCertResp, error)
}

// validateVerifyIakAndIDevIDCertsReq verifies that VerifyIakAndIDevIDCertsReq request is valid.
func validateVerifyIakAndIDevIDCertsReq(req *VerifyIakAndIDevIDCertsReq) error {
	if req == nil {
		return fmt.Errorf("request VerifyIakAndIDevIDCertsReq is nil")
	}
	if req.ControlCardID == nil {
		return fmt.Errorf("field ControlCardID in VerifyIakAndIDevIDCertsReq request is nil")
	}

	return nil
}

// VerifyIakAndIDevIDCerts is  the default/reference implementation of TpmCertVerifier.VerifyIakAndIDevIDCerts().
func VerifyIakAndIDevIDCerts(req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error) {
	err := validateVerifyIakAndIDevIDCertsReq(req)
	if err != nil {
		return nil, fmt.Errorf("invalid request VerifyIakAndIDevIDCertsReq to VerifyIakAndIDevIDCerts(): %v", err)
	}
	iakX509, err := VerifyAndParsePemCert(req.IakCertPem, req.CertVerificationOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and parse IAK cert: %v", err)
	}
	log.Info("Successfully verified and parsed IAK cert")

	iDevIDX509, err := VerifyAndParsePemCert(req.IDevIDCertPem, req.CertVerificationOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and parse IDevID cert: %v", err)
	}
	log.Info("Successfully verified and parsed IDevID cert")

	// Verify IAK and IDevID cert subject serials match.
	if diff := cmp.Diff(iakX509.Subject.SerialNumber, iDevIDX509.Subject.SerialNumber); diff != "" {
		return nil, fmt.Errorf("subject serial numbers of IAK and IDevID certs do not match: diff = %v", diff)
	}
	log.Infof("Subject serial numbers of IAK and IDevID certs match: %s", iakX509.Subject.SerialNumber)

	// Verify IAK/IDevID cert subject serial and expected control card serial numbers match.
	if diff := cmp.Diff(iakX509.Subject.SerialNumber, req.ControlCardID.ControlCardSerial); diff != "" {
		return nil, fmt.Errorf("subject serial number in IAK/IDevID cert and expected control card serial from request do not match: diff = %v", diff)
	}
	log.Infof("Subject serial number in IAK/IDevID cert and expected control card serial from request match: %s", iakX509.Subject.SerialNumber)

	// Verify and convert IAK and IDevID certs' pub keys to PEM.
	iakPubPem, err := VerifyAndSerializePubKey(iakX509)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and serialize IAK pub key: %v", err)
	}
	log.Infof("Successfully verified and parsed IAK pub key PEM %s", iakPubPem)

	iDevIDPubPem, err := VerifyAndSerializePubKey(iDevIDX509)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and serialize IDevID pub key: %v", err)
	}
	log.Infof("Successfully verified and parsed IDevID pub key PEM %s", iDevIDPubPem)

	return &VerifyIakAndIDevIDCertsResp{
		IakPubPem:    iakPubPem,
		IDevIDPubPem: iDevIDPubPem,
	}, nil
}

// validateVerifyTpmCertReq verifies that VerifyTpmCertReq request is valid.
func validateVerifyTpmCertReq(req *VerifyTpmCertReq) error {
	if req == nil {
		return fmt.Errorf("request VerifyTpmCertReq is nil")
	}
	if req.ControlCardID == nil {
		return fmt.Errorf("field ControlCardID in VerifyTpmCertReq request is nil")
	}

	return nil
}

// VerifyTpmCert is the default/reference implementation of TpmCertVerifier.VerifyTpmCert().
func VerifyTpmCert(req *VerifyTpmCertReq) (*VerifyTpmCertResp, error) {
	err := validateVerifyTpmCertReq(req)
	if err != nil {
		return nil, fmt.Errorf("invalid request VerifyTpmCertReq to VerifyTpmCert(): %v", err)
	}
	certX509, err := VerifyAndParsePemCert(req.CertPem, req.CertVerificationOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and parse PEM cert: %v", err)
	}
	log.Info("Successfully verified and parsed PEM cert into x509 structure")

	// Verify IAK/IDevID cert subject serial and expected control card serial numbers match.
	if diff := cmp.Diff(certX509.Subject.SerialNumber, req.ControlCardID.ControlCardSerial); diff != "" {
		return nil, fmt.Errorf("subject serial number in IAK/IDevID cert and expected control card serial from request do not match: diff = %v", diff)
	}
	log.Infof("Subject serial number in IAK/IDevID cert and expected control card serial from request match: %s", certX509.Subject.SerialNumber)

	// Verify and convert x509 cert pub key to PEM.
	pubKeyPem, err := VerifyAndSerializePubKey(certX509)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and serialize cert's pub key: %v", err)
	}
	log.Infof("Successfully verified and parsed pub key PEM %s", pubKeyPem)

	return &VerifyTpmCertResp{
		PubPem: pubKeyPem,
	}, nil
}

// VerifyAndParsePemCert parses PEM (IAK or IDevID) cert, verifies it and returns the parsed x509 structure.
func VerifyAndParsePemCert(certPem string, certVerificationOpts x509.VerifyOptions) (*x509.Certificate, error) {
	if certVerificationOpts.Roots == nil {
		return nil, fmt.Errorf("invalid request to VerifyAndParsePemCert(): x509.VerifyOptions.Roots is nil")
	}

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

// VerifyAndSerializePubKey fetches (IAK or IDevID) public key from x509 cert, validates the key and returns it in the PEM format.
func VerifyAndSerializePubKey(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("invalid request to VerifyAndSerializePubKey(): x509.Certificate is nil")
	}
	if cert.PublicKey == nil {
		return "", fmt.Errorf("invalid request to VerifyAndSerializePubKey(): x509.Certificate.PublicKey is nil")
	}
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
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derPub,
		})
	return string(pubKeyPem), nil
}
