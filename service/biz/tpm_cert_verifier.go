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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

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
	VerifyIakAndIDevIDCerts(ctx context.Context, req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error)

	// Performs the following:
	// 1. Validate (signature and expiration) a TPM-based cert such as IAK or IDevID.
	// 2. Parse pub key from the cert and validate it (accepted crypto algo and key length).
	VerifyTpmCert(ctx context.Context, req *VerifyTpmCertReq) (*VerifyTpmCertResp, error)
}

// DefaultTpmCertVerifier is the default/reference implementation of TpmCertVerifier.
type DefaultTpmCertVerifier struct{}

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

// getCertSerialNumber extracts the serial number from the cert subject serial number.
func getCertSerialNumber(serial string) (string, error) {
	// iakX509.Subject.SerialNumber can come in the format PID:xxxxxxx SN:1234JF or just
	// the serial number as is.
	// Try to extract out the value after SN:
	sn := strings.Split(serial, "SN:")
	if len(sn) != 2 {
		return sn[0], nil
	}
	return sn[1], nil
}

// VerifyIakAndIDevIDCerts is the default/reference implementation of TpmCertVerifier.VerifyIakAndIDevIDCerts().
func (tcv *DefaultTpmCertVerifier) VerifyIakAndIDevIDCerts(ctx context.Context, req *VerifyIakAndIDevIDCertsReq) (*VerifyIakAndIDevIDCertsResp, error) {
	err := validateVerifyIakAndIDevIDCertsReq(req)
	if err != nil {
		err = fmt.Errorf("invalid request VerifyIakAndIDevIDCertsReq to VerifyIakAndIDevIDCerts(): %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	iakX509, err := VerifyAndParsePemCert(ctx, req.IakCertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse IAK cert: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed IAK cert")

	// Verify IAK cert subject serial and expected control card serial numbers match.
	iakSerialNumber, err := getCertSerialNumber(iakX509.Subject.SerialNumber)
	if err != nil {
		err = fmt.Errorf("failed to get serial number from IAK cert subject serial %v: %v", iakX509.Subject.SerialNumber, err)
		log.ErrorContext(ctx, err)
		return nil, err
	}

	if iakSerialNumber != req.ControlCardID.GetChassisSerialNumber() && iakSerialNumber != req.ControlCardID.GetControlCardSerial() {
		err := fmt.Errorf("mismatched subject serial number: IAK certs' is %v and chassis serial from request's is %v, and control card serial is %v",
			iakSerialNumber, req.ControlCardID.GetChassisSerialNumber(), req.ControlCardID.GetControlCardSerial())
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Subject serial number in IAK/IDevID cert and expected control card or chassis serial from request match: %s", iakX509.Subject.SerialNumber)

	// Verify and convert IAK certs' pub keys to PEM.
	iakPubPem, err := VerifyAndSerializePubKey(ctx, iakX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize IAK pub key: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed IAK pub key PEM %s", iakPubPem)

	// IDevID cert is needed on the primary control card. On the secondary
	// it is only needed if no direct communication to the primary control card
	// is possible.
	if req.IDevIDCertPem == "" {
		return &VerifyIakAndIDevIDCertsResp{
			IakPubPem: iakPubPem,
		}, nil
	}

	iDevIDX509, err := VerifyAndParsePemCert(ctx, req.IDevIDCertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse IDevID cert: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed IDevID cert")

	// Verify IAK and IDevID cert subject serials match.
	iDevIDSerialNumber, err := getCertSerialNumber(iDevIDX509.Subject.SerialNumber)
	if err != nil {
		err = fmt.Errorf("failed to get serial number from iDevID cert subject serial %v: %v", iakX509.Subject.SerialNumber, err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	if iakSerialNumber != iDevIDSerialNumber {
		err = fmt.Errorf("mismatched subject serial numbers. IAK's is %v and IDevID certs' is %v",
			iakSerialNumber, iDevIDSerialNumber)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Subject serial numbers of IAK and IDevID certs match: %s", iakSerialNumber)

	// Verify and convert IDevID certs' pub keys to PEM.
	iDevIDPubPem, err := VerifyAndSerializePubKey(ctx, iDevIDX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize IDevID pub key: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed IDevID pub key PEM %s", iDevIDPubPem)

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
func (tcv *DefaultTpmCertVerifier) VerifyTpmCert(ctx context.Context, req *VerifyTpmCertReq) (*VerifyTpmCertResp, error) {
	err := validateVerifyTpmCertReq(req)
	if err != nil {
		err = fmt.Errorf("invalid request VerifyTpmCertReq to VerifyTpmCert(): %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	certX509, err := VerifyAndParsePemCert(ctx, req.CertPem, req.CertVerificationOpts)
	if err != nil {
		err = fmt.Errorf("failed to verify and parse PEM cert: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContext(ctx, "Successfully verified and parsed PEM cert into x509 structure")

	// Verify IAK/IDevID cert subject serial and expected control card serial numbers match.
	if certX509.Subject.SerialNumber != req.ControlCardID.GetControlCardSerial() {
		err = fmt.Errorf("mismatched subject serial number. IAK/IDevID certs' is %v and expected control card serial from request's is %v",
			certX509.Subject.SerialNumber, req.ControlCardID.GetControlCardSerial())
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Subject serial number in IAK/IDevID cert and expected control card serial from request match: %s", certX509.Subject.SerialNumber)

	// Verify and convert x509 cert pub key to PEM.
	pubKeyPem, err := VerifyAndSerializePubKey(ctx, certX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize cert's pub key: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed pub key PEM %s", pubKeyPem)

	return &VerifyTpmCertResp{
		PubPem: pubKeyPem,
	}, nil
}

// VerifyAndParsePemCert parses PEM (IAK or IDevID) cert, verifies it and returns the parsed x509 structure.
func VerifyAndParsePemCert(ctx context.Context, certPem string, certVerificationOpts x509.VerifyOptions) (*x509.Certificate, error) {
	// Convert PEM to DER.
	certDer, _ := pem.Decode([]byte(certPem))
	if certDer == nil {
		err := fmt.Errorf("failed to decode cert PEM into DER cert_pem=%s", certPem)
		log.ErrorContext(ctx, err)
		return nil, err

	}
	// Parse DER cert into structured x509 object.
	x509CertParsed, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse cert DER into x509 structure cert_pem=%s: %v", certPem, err)
		log.ErrorContext(ctx, err)
		return nil, err
	}

	// Validate cert expiration and verify signature using provided options.
	if _, err := x509CertParsed.Verify(certVerificationOpts); err != nil {
		err = fmt.Errorf("failed to verify certificate_pem=%s: %v", certPem, err)
		log.ErrorContext(ctx, err)
		return nil, err
	}

	return x509CertParsed, nil
}

// VerifyAndSerializePubKey fetches (IAK or IDevID) public key from x509 cert, validates the key and returns it in the PEM format.
func VerifyAndSerializePubKey(ctx context.Context, cert *x509.Certificate) (string, error) {
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
		log.InfoContextf(ctx, "pub key algorithm is %s %d", cert.PublicKeyAlgorithm, pubKeyLen)
	case *ecdsa.PublicKey:
		pubKeyLen := certPubKey.Curve.Params().BitSize
		if pubKeyLen < 384 {
			return "", fmt.Errorf("pub ECC key must be 384 bits or higher, but was %d", pubKeyLen)
		}
		log.InfoContextf(ctx, "pub key algorithm is %s %d", cert.PublicKeyAlgorithm, pubKeyLen)
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
