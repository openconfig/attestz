// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package caservice

import (
	"context"
	"crypto/x509"
	"fmt"
)

// PKIProvider defines the Public Key Infrastructure interface required by the Enrollz SUT controller.
//
// Implementations must provide two core PKI capabilities:
//  1. Device Trust Anchors: Authoritative Root CAs to authenticate the device's factory identity (IDevID and IAK).
//  2. Owner CA Authority: Signing capabilities (private key / CA service) to mint and issue new owner certificates
//     (oIAK and oIDevID) for the device.
type PKIProvider interface {
	// DeviceTrustBundle returns an x509.CertPool containing the authoritative Root CA certificates
	// used to authenticate the device's factory identity certificates (IDevID and IAK).
	//
	// Implementation Guidance:
	// - Return an x509.CertPool containing the trusted Root CA certificates for the devices under test.
	// - The test suite validates the following device certificates against this trust bundle:
	//     1. The Initial Device Identifier (IDevID) certificate.
	//     2. The Initial Attestation Key (IAK) certificate.
	DeviceTrustBundle() *x509.CertPool

	// IssueOIAK generates an Owner Initial Attestation Key (oIAK) certificate.
	//
	// Implementation Guidance:
	// 1. Input: `iakPEM` is the PEM-encoded IAK certificate from the DUT.
	// 2. Extract the public key associated with the IAK.
	// 3. Construct an X.509 certificate signed by the Owner CA with:
	//    - Key Usage: `x509.KeyUsageDigitalSignature` (required for TPM quote signing).
	// 4. Output: Return the PEM-encoded oIAK certificate string to be installed onto the DUT.
	IssueOIAK(iakPEM string) (string, error)

	// IssueOIDevID generates an Owner Initial Device Identifier (oIDevID) certificate.
	//
	// Implementation Guidance:
	// 1. Input: `idevidPEM` is the PEM-encoded IDevID certificate from the DUT.
	// 2. Extract the public key from the IDevID certificate.
	// 3. Construct an X.509 certificate signed by the Owner CA with:
	//    - Key Usage: `x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment`.
	//    - Extended Key Usage: Must include `x509.ExtKeyUsageServerAuth` to allow the DUT to
	//      authenticate itself when serving management services (gNMI, gNOI, gNSI) over mTLS.
	// 4. Output: Return the PEM-encoded oIDevID certificate string to be installed onto the DUT.
	IssueOIDevID(idevidPEM string) (string, error)

	// GenerateClientCredentials produces an ephemeral or mTLS client certificate and private key pair
	// for the SUT controller to authenticate itself when connecting to the DUT's enrollment service.
	//
	// Implementation Guidance:
	// - Generate or retrieve a client certificate signed by a CA that the device trusts during enrollment.
	// - Returns `certPEM` (PEM-encoded client certificate) and `keyPEM` (PEM-encoded PKCS#8 private key).
	GenerateClientCredentials() (certPEM, keyPEM []byte, err error)
}

// NewEngine is a placeholder constructor for Engine.
// Implementers should replace this with their concrete PKI constructor.
func NewEngine(ctx context.Context, vendorCACert, ownerCACert, ownerCAKey string) (PKIProvider, error) {
	return &Engine{}, nil
}

// Engine is a minimal reference implementation skeleton for PKIProvider.
// Implementers should replace or extend this with their concrete PKI logic.
type Engine struct{}

var _ PKIProvider = (*Engine)(nil)

// DeviceTrustBundle returns the authoritative Root CA certificates for the DUT.
func (e *Engine) DeviceTrustBundle() *x509.CertPool {
	return nil
}

// IssueOIAK generates an Owner Initial Attestation Key (oIAK) certificate.
//
// Implementation Guidance:
// 1. Decode the PEM-encoded IAK certificate (iakPEM) received from the DUT.
// 2. Extract the public key associated with the IAK.
// 3. Construct an X.509 certificate signed by the Owner CA with KeyUsage = x509.KeyUsageDigitalSignature.
// 4. Return the PEM-encoded certificate string.
func (e *Engine) IssueOIAK(iakPEM string) (string, error) {
	return "", fmt.Errorf("IssueOIAK is not implemented: please implement custom PKI logic per the PKIProvider interface guidance")
}

// IssueOIDevID generates an Owner Initial Device Identifier (oIDevID) certificate.
//
// Implementation Guidance:
// 1. Decode the PEM-encoded IDevID certificate (idevidPEM) received from the DUT.
// 2. Extract the public key from the IDevID certificate.
// 3. Construct an X.509 certificate signed by the Owner CA with ExtKeyUsage = [ServerAuth].
// 4. Return the PEM-encoded certificate string.
func (e *Engine) IssueOIDevID(idevidPEM string) (string, error) {
	return "", fmt.Errorf("IssueOIDevID is not implemented: please implement custom PKI logic per the PKIProvider interface guidance")
}

// GenerateClientCredentials produces client credentials for mutual TLS authentication with the DUT.
//
// Implementation Guidance:
// 1. Generate an RSA or ECDSA private key.
// 2. Generate a client certificate signed by a CA trusted by the device.
// 3. Encode both to PEM format and return certPEM and keyPEM.
func (e *Engine) GenerateClientCredentials() (certPEM, keyPEM []byte, err error) {
	return nil, nil, fmt.Errorf("GenerateClientCredentials is not implemented: please implement custom PKI credential generation per the PKIProvider interface guidance")
}
