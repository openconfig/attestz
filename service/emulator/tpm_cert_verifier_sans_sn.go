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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	log "github.com/golang/glog"
	"github.com/openconfig/attestz/service/biz"
)

// TpmCertVerifierSansSerial is a TPM Cert Verifier that skips the serial number checks for emulator purposes only.
type TpmCertVerifierSansSerial struct{}

// validateVerifyIakAndIDevIDCertsReq verifies that VerifyIakAndIDevIDCertsReq request is valid.
func validateVerifyIakAndIDevIDCertsReq(req *biz.VerifyIakAndIDevIDCertsReq) error {
	if req == nil {
		return fmt.Errorf("request VerifyIakAndIDevIDCertsReq is nil")
	}
	if req.ControlCardID == nil {
		return fmt.Errorf("field ControlCardID in VerifyIakAndIDevIDCertsReq request is nil")
	}

	return nil
}

// VerifyIakAndIDevIDCerts is an implementation of biz.TpmCertVerifier.VerifyIakAndIDevIDCerts() that skips the serial number checks for emulator purposes only.
func (tcv *TpmCertVerifierSansSerial) VerifyIakAndIDevIDCerts(ctx context.Context, req *biz.VerifyIakAndIDevIDCertsReq) (*biz.VerifyIakAndIDevIDCertsResp, error) {
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
		return &biz.VerifyIakAndIDevIDCertsResp{
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

	// Verify and convert IDevID certs' pub keys to PEM.
	iDevIDPubPem, err := VerifyAndSerializePubKey(ctx, iDevIDX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize IDevID pub key: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed IDevID pub key PEM %s", iDevIDPubPem)

	return &biz.VerifyIakAndIDevIDCertsResp{
		IakPubPem:    iakPubPem,
		IDevIDPubPem: iDevIDPubPem,
	}, nil
}

// validateVerifyTpmCertReq verifies that VerifyTpmCertReq request is valid.
func validateVerifyTpmCertReq(req *biz.VerifyTpmCertReq) error {
	if req == nil {
		return fmt.Errorf("request VerifyTpmCertReq is nil")
	}
	if req.ControlCardID == nil {
		return fmt.Errorf("field ControlCardID in VerifyTpmCertReq request is nil")
	}

	return nil
}

// VerifyTpmCert is an implementation of biz.TpmCertVerifier.VerifyTpmCert() that skips the serial number checks for emulator purposes only.
func (tcv *TpmCertVerifierSansSerial) VerifyTpmCert(ctx context.Context, req *biz.VerifyTpmCertReq) (*biz.VerifyTpmCertResp, error) {
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

	// Verify and convert x509 cert pub key to PEM.
	pubKeyPem, err := VerifyAndSerializePubKey(ctx, certX509)
	if err != nil {
		err = fmt.Errorf("failed to verify and serialize cert's pub key: %v", err)
		log.ErrorContext(ctx, err)
		return nil, err
	}
	log.InfoContextf(ctx, "Successfully verified and parsed pub key PEM %s", pubKeyPem)

	return &biz.VerifyTpmCertResp{
		PubPem: pubKeyPem,
	}, nil
}

// VerifyAndParsePemCert parses PEM (IAK or IDevID) cert, verifies it and returns the parsed x509 structure.
func VerifyAndParsePemCert(ctx context.Context, certPem string, certVerificationOpts x509.VerifyOptions) (*x509.Certificate, error) {
	certs, err := parseCertChain(ctx, certPem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert chain: %v", err)
	}
	leafCert := certs[0]
	// If the PEM string contained more than one cert, treat others as intermediates.
	if len(certs) > 1 {
		if certVerificationOpts.Intermediates == nil {
			certVerificationOpts.Intermediates = x509.NewCertPool()
		}
		for _, cert := range certs[1:] {
			certVerificationOpts.Intermediates.AddCert(cert)
		}
	}

	// TODO: Move this configuration to the caller. Add more granular verification option per-cert type rather than having blanket ExtKeyUsageAny.
	// We relax the key usage requirement to ExtKeyUsageAny here because
	// IAKs are not standard TLS endpoints and might not have standard TLS usages.
	certVerificationOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	// Validate cert expiration and verify signature using provided options.
	if _, err := leafCert.Verify(certVerificationOpts); err != nil {
		err = fmt.Errorf("failed to verify certificate_pem=%s: %v", certPem, err)
		log.ErrorContext(ctx, err)
		return nil, err
	}

	return leafCert, nil
}

// parseCertChain parses the cert chain PEM data into leaf and intermediate *x509.Certificate
// objects and returns them in the order of leaf -> intermediate -> root.
func parseCertChain(ctx context.Context, certChainPem string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	pemData := []byte(certChainPem)
	if len(pemData) == 0 {
		return nil, fmt.Errorf("no certificate found in provided PEM data")
	}

	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			log.InfoContextf(ctx, "Skipping non-certificate PEM block: %v", block.Type)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// This could happen if the PEM block is malformed.
			return nil, fmt.Errorf("PEM block is malformed: %w", err)
		}

		log.InfoContextf(ctx, "Parsed certificate: %+v", cert)
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in provided PEM data")
	}

	return certs, nil
}

// VerifyAndSerializePubKey fetches (IAK or IDevID) public key from x509 cert, validates the key and returns it in the PEM format.
func VerifyAndSerializePubKey(ctx context.Context, cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("invalid request to VerifyAndSerializePubKey(): x509.Certificate is nil")
	}
	if cert.PublicKey == nil {
		return "", fmt.Errorf("invalid request to VerifyAndSerializePubKey(): x509.Certificate.PublicKey is nil")
	}

	// Verify the underlying pub key is ECC P256 (or higher) or RSA 2048 (or higher).
	// RSA and ECC P256 are supported here for legacy implementations. New
	// platforms should not support these cryptographic algorithms.
	switch certPubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubKeyLen := certPubKey.Size() * 8
		if pubKeyLen < 2048 {
			return "", fmt.Errorf("pub RSA key must be 2048 bits or higher, but was %d", pubKeyLen)
		}
		log.InfoContextf(ctx, "pub key algorithm is %s %d", cert.PublicKeyAlgorithm, pubKeyLen)
	case *ecdsa.PublicKey:
		pubKeyLen := certPubKey.Curve.Params().BitSize
		if pubKeyLen < 256 {
			return "", fmt.Errorf("pub ECC key must be 256 bits or higher, but was %d", pubKeyLen)
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
