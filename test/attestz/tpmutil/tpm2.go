// Package tpmutil contains helper functions for TPM 2.0 operations and remote attestation verification.
package tpmutil

import (
	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// TPMCertUtils defines the TPM 2.0 certificate and key utility interface required by the
// Attestz SUT controller and verification suite.
//
// Implementations should follow TCG specifications (v1.10r9, Section 7.4.4; see
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf)
// for Initial Attestation Key (IAK) and Initial Device ID (IDevID) certificate profiles and TPMTPublic key templates.
type TPMCertUtils interface {
	// ToTPMTPublic converts the public key of an X.509 certificate into a TPM 2.0 TPMTPublic
	// structure matching the device's key template parameters.
	ToTPMTPublic(cert *x509.Certificate) (*tpm2.TPMTPublic, error)

	// IsIAK reports whether the provided X.509 certificate is a valid Initial Attestation Key
	// (IAK) certificate.
	IsIAK(cert *x509.Certificate) (bool, error)

	// IsIDevID reports whether the provided X.509 certificate is a valid Initial Device ID
	// (IDevID) certificate.
	IsIDevID(cert *x509.Certificate) (bool, error)
}

// tpmCertUtilsImpl is a minimal reference implementation skeleton for TPMCertUtils.
// Implementers should replace or extend this with their concrete TPM certificate logic.
type tpmCertUtilsImpl struct{}

var _ TPMCertUtils = (*tpmCertUtilsImpl)(nil)

// NewTPMCertUtils is a placeholder constructor for TPMCertUtils.
// Implementers should replace this with their concrete TPMCertUtils constructor.
func NewTPMCertUtils() TPMCertUtils {
	return &tpmCertUtilsImpl{}
}

// ToTPMTPublic converts the public key of an X.509 certificate into a TPMTPublic structure.
func (u *tpmCertUtilsImpl) ToTPMTPublic(cert *x509.Certificate) (*tpm2.TPMTPublic, error) {
	return nil, fmt.Errorf("ToTPMTPublic is not implemented: please implement custom TPM key conversion logic per the TPMCertUtils interface")
}

// IsIAK reports whether the provided certificate is an Initial Attestation Key (IAK).
func (u *tpmCertUtilsImpl) IsIAK(cert *x509.Certificate) (bool, error) {
	return false, fmt.Errorf("IsIAK is not implemented: please implement custom IAK certificate verification per the TPMCertUtils interface")
}

// IsIDevID reports whether the provided certificate is an Initial Device ID (IDevID).
func (u *tpmCertUtilsImpl) IsIDevID(cert *x509.Certificate) (bool, error) {
	return false, fmt.Errorf("IsIDevID is not implemented: please implement custom IDevID certificate verification per the TPMCertUtils interface")
}
