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

// Package biz contains the infra-agnostic business logic of Enrollz Service hosted by the switch owner infra.
package biz

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"

	log "github.com/golang/glog"

	tpm20 "github.com/google/go-tpm/tpm2"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

var (
	// ErrInvalidCertifyInfo is returned when the certify info data is invalid.
	ErrInvalidCertifyInfo = errors.New("invalid certify info")
	// ErrCertifiedWrongName is returned when the certified name is invalid.
	ErrCertifiedWrongName = errors.New("certified wrong name")
)

// TCGCSRIDevIDContents is the contents of the TCG_CSR_IDEVID_CONTENT structure.
type TCGCSRIDevIDContents struct {
	StructVer                uint32              // Version of the TCG_CSR_IDEVID_CONTENT structure
	HashAlgoID               uint32              // TCG algorithm identifier for the hash field
	Hash                     []byte              // Hash of everything that follows in TCG_CSR_IDEVID_CONTENT
	ProdModel                string              // Product Model string
	ProdSerial               string              // Product Serial string
	EKCert                   string              // Endorsement Key Certificate PEM encoded(X.509)
	IAKPub                   tpm20.TPMTPublic    // Attestation Key public key (IAK)(TPMT_PUBLIC structure)
	IDevIDPub                tpm20.TPMTPublic    // Signing Key public key (TPMT_PUBLIC structure)
	SignCertifyInfo          tpm20.TPMSAttest    // IDevID certification data(TPMS_ATTEST structure)
	SignCertifyInfoSignature tpm20.TPMTSignature // Signature of the SignCertifyInfo field (TPMTSignature structure)
}

// TPM20Utils is an interface for TPM 2.0 utility functions.
// This interface was created to allow for mocking of the TPM 2.0 utility functions in unit tests
// since it is not possible to test the TPM 2.0  no-IDevID flow with stubbed data.
type TPM20Utils interface {
	ParseTCGCSRIDevIDContent(csrBytes []byte) (*TCGCSRIDevIDContents, error)
	GenerateRestrictedHMACKey() (*tpm20.TPMTPublic, *tpm20.TPMTSensitive)
	WrapHMACKeytoRSAPublicKey(rsaPub *rsa.PublicKey, hmacPub *tpm20.TPMTPublic,
		hmacSensitive *tpm20.TPMTSensitive) ([]byte, []byte, error)
	VerifyHMAC(message []byte, signature []byte, hmacSensitive *tpm20.TPMTSensitive) error
	VerifyCertifyInfo(certifyInfoAttest *tpm20.TPMSAttest, certifiedKey *tpm20.TPMTPublic) error
	VerifyIAKAttributes(iakPub *tpm20.TPMTPublic) error
	VerifyTPMTSignature(pubKey *tpm20.TPMTPublic, signature *tpm20.TPMTSignature, data []byte) error
	VerifyIDevIDAttributes(idevidPub *tpm20.TPMTPublic, keyTemplate epb.KeyTemplate) error
}

// DefaultTPM20Utils is a concrete implementation of the TPM20Utils interface.
type DefaultTPM20Utils struct{}

// readNonZeroUint23 is a helper function to read a non-zero 4-byte Big Endian unsigned integer.
func readNonZeroUint32(r *bytes.Reader) (uint32, error) {
	var val uint32
	err := binary.Read(r, binary.BigEndian, &val)
	if err != nil {
		return 0, fmt.Errorf("failed to read uint32: %w", err)
	}
	if val == 0 {
		return 0, fmt.Errorf("read uint32 is zero, expected non-zero")
	}
	return val, nil
}

// readUint32 is a helper function to read a 4-byte Big Endian unsigned integer.
func readUint32(r *bytes.Reader) (uint32, error) {
	var val uint32
	err := binary.Read(r, binary.BigEndian, &val)
	if err != nil {
		return 0, fmt.Errorf("failed to read uint32: %w", err)
	}
	return val, nil
}

// readBytes is a helper function to read a specified number of bytes.
func readBytes(r *bytes.Reader, size uint32) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil // Return empty slice for size 0
	}
	buf := make([]byte, size)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read %d bytes: %w", size, err)
	}
	if n != int(size) {
		return nil, fmt.Errorf("expected to read %d bytes, but read %d", size, n)
	}
	return buf, nil
}

// certificateDerToPem converts DER-encoded X.509 certificate bytes to PEM format.
func certificateDerToPem(derBytes []byte) (string, error) {
	if len(derBytes) == 0 {
		return "", nil // Return empty string for empty input
	}
	// Attempt to parse as an X.509 certificate to validate
	if _, err := x509.ParseCertificate(derBytes); err != nil {
		// Log a warning if parsing fails, but still encode to PEM
		return "", fmt.Errorf("Failed to parse DER certificate with x509: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// GenerateRestrictedHMACKey generates a restricted HMAC key.
func GenerateRestrictedHMACKey() (*tpm20.TPMTPublic, *tpm20.TPMTSensitive) {
	// TODO: Implement this function.
	return &tpm20.TPMTPublic{}, &tpm20.TPMTSensitive{}
}

// RSAPublicKeyToTPMTPublic converts an RSA public key to a TPMT_PUBLIC struct.
func (u *DefaultTPM20Utils) RSAPublicKeyToTPMTPublic(rsaPublicKey *rsa.PublicKey) (tpm20.TPMTPublic, error) {
	// TODO: Implement this function.
	tpmPublicKey := tpm20.TPMTPublic{}
	return tpmPublicKey, nil
}

// WrapHMACKeytoRSAPublicKey wraps the HMAC key to the RSA public key.
func (u *DefaultTPM20Utils) WrapHMACKeytoRSAPublicKey(rsaPub *rsa.PublicKey, hmacPub *tpm20.TPMTPublic,
	hmacSensitive *tpm20.TPMTSensitive) ([]byte, []byte, error) {
	// Convert RSA public key to TPMTPublic.
	_, err := u.RSAPublicKeyToTPMTPublic(rsaPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert RSA public key to TPMTPublic: %w", err)
	}
	// TODO: Implement this function.
	return []byte{}, []byte{}, nil
}

// VerifyHMAC verifies the HMAC signature of the message.
func (u *DefaultTPM20Utils) VerifyHMAC(message []byte, signature []byte, hmacSensitive *tpm20.TPMTSensitive) error {
	// TODO: Implement this function.
	return nil
}

// VerifyCertifyInfo verifies the certify info (TPM2B_ATTEST) and the nested TPMS_CERTIFY_INFO structure.
func (u *DefaultTPM20Utils) VerifyCertifyInfo(certifyInfoAttest *tpm20.TPMSAttest, certifiedKey *tpm20.TPMTPublic) error {
	if certifyInfoAttest.Magic != tpm20.TPMGeneratedValue {
		return fmt.Errorf("%w: unexpected TPM2B_ATTEST magic %0x", ErrInvalidCertifyInfo, certifyInfoAttest.Magic)
	}

	if certifyInfoAttest.Type != tpm20.TPMSTAttestCertify {
		return fmt.Errorf("%w: unexpected TPM2B_ATTEST type %0x", ErrInvalidCertifyInfo, certifyInfoAttest.Type)
	}

	keyName, err := tpm20.ObjectName(certifiedKey)
	if err != nil {
		return fmt.Errorf("failed to get key name: %v", err)
	}

	certifyInfo, err := certifyInfoAttest.Attested.Certify()
	if err != nil {
		return fmt.Errorf("failed to get certify info: %w", err)
	}

	// Check that the certified Name is the same as we expected.
	if !bytes.Equal(keyName.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: expected Name %x, certified Name was %x", ErrCertifiedWrongName, keyName.Buffer, certifyInfo.Name.Buffer)
	}

	// Sanity check that the certified QualifiedName is not the same as the Name for some reason.
	if bytes.Equal(certifyInfo.QualifiedName.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: QualifiedName (%x) unexpectedly matched Name (%x)", ErrCertifiedWrongName, certifyInfo.QualifiedName.Buffer, certifyInfo.Name.Buffer)
	}
	return nil
}

// VerifyIAKAttributes verifies the IAK attributes.
func (u *DefaultTPM20Utils) VerifyIAKAttributes(iakPub *tpm20.TPMTPublic) error {
	// TODO: Implement this function.
	return nil
}

// VerifyTPMTSignature verifies the TPMT_SIGNATURE structure using the given public key.
func (u *DefaultTPM20Utils) VerifyTPMTSignature(pubKey *tpm20.TPMTPublic, signature *tpm20.TPMTSignature, data []byte) error {
	// TODO: Implement this function.
	return nil
}

// VerifyIDevIDAttributes verifies the IDevID attributes and make sure they match the template provided.
func (u *DefaultTPM20Utils) VerifyIDevIDAttributes(idevidPub *tpm20.TPMTPublic, keyTemplate epb.KeyTemplate) error {
	// TODO: Implement this function.
	return nil
}

// ParseTCGCSRIDevIDContent parses the TCG_CSR_IDEVID_CONTENT structure from a byte slice
// and returns a TCGCSRIDevIDContents struct.
// Ref: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf#page=71
func ParseTCGCSRIDevIDContent(csrBytes []byte) (*TCGCSRIDevIDContents, error) {
	reader := bytes.NewReader(csrBytes)
	result := &TCGCSRIDevIDContents{}

	// Read the first few fields and the sizes of the fields in the TCG_CSR_IDEVID_CONTENT structure.

	// structVer (4 bytes) - Version of the TCG_CSR_IDEVID_CONTENT structure
	structVer, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.structVer: %w", err)
	}
	result.StructVer = structVer

	// hashAlgoId (4 bytes) - TCG algorithm identifier for the hash field
	hashAlgoID, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.hashAlgoId: %w", err)
	}
	result.HashAlgoID = hashAlgoID

	// hashSize (4 bytes)
	hashSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.hashSize: %w", err)
	}
	// hash - Hash of everything that follows in TCG_CSR_IDEVID_CONTENT
	hash, err := readBytes(reader, hashSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.hash (size %d): %w", hashSize, err)
	}
	result.Hash = hash

	// prodModelSize (4 bytes)
	prodModelSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodModelSize: %w", err)
	}

	// prodSerialSize (4 bytes)
	prodSerialSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodSerialSize: %w", err)
	}

	// prodCaDataSize (4 bytes)
	prodCaDataSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodCaDataSize: %w", err)
	}

	// bootEventLogSize (4 bytes)
	bootEventLogSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.bootEvntLogSize: %w", err)
	}

	// ekCertSize (4 bytes)
	ekCertSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.ekCertSize: %w", err)
	}

	// attestPubSize (4 bytes)
	attestPubSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.attestPubSize: %w", err)
	}

	// atCreateTktSize (4 bytes)
	atCreateTktSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCreateTktSize: %w", err)
	}

	// atCertifyInfoSize (4 bytes)
	atCertifyInfoSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifyInfoSize: %w", err)
	}

	// atCertifiyInfoSignatureSize (4 bytes)
	atCertifiyInfoSignatureSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifiyInfoSignatureSize: %w", err)
	}

	// signingPubSize (4 bytes)
	signingPubSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signingPubSize: %w", err)
	}

	// SignCertifyInfoSize (4 bytes)
	signCertifyInfoSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSize: %w", err)
	}

	// SignCertifyInfoSignatureSize (4 bytes)
	signCertifyInfoSignatureSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSignatureSize: %w", err)
	}

	// padSize - may or may not be zero(4 bytes)
	var padSize uint32
	err = binary.Read(reader, binary.BigEndian, &padSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.padSize: %w", err)
	}

	// prodModel - product model string
	prodModelBytes, err := readBytes(reader, prodModelSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodModel (size %d): %w", prodModelSize, err)
	}
	result.ProdModel = string(prodModelBytes)

	// prodSerial - product serial string
	prodSerialBytes, err := readBytes(reader, prodSerialSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodSerial (size %d): %w", prodSerialSize, err)
	}
	result.ProdSerial = string(prodSerialBytes)

	// prodCaData - product CA data
	_, err = readBytes(reader, prodCaDataSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodCaData (size %d): %w", prodCaDataSize, err)
	}

	// bootEventLog - boot event log
	_, err = readBytes(reader, bootEventLogSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.bootEventLog (size %d): %w", bootEventLogSize, err)
	}

	// ekCert - Endorsement Key Certificate PEM encoded(X.509)
	ekCertBytes, err := readBytes(reader, ekCertSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.ekCert (size %d): %w", ekCertSize, err)
	}
	ekCert, err := certificateDerToPem(ekCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert EK Cert to PEM: %w", err)
	}
	result.EKCert = ekCert

	// attestPub - Attestation Key public key (IAK)
	attestPubBytes, err := readBytes(reader, attestPubSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.attestPub (size %d): %w", attestPubSize, err)
	}
	attestPubTPMT, err := tpm20.Unmarshal[tpm20.TPMTPublic](attestPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestPubBytes to TPMTPublic: %w", err)
	}
	result.IAKPub = *attestPubTPMT

	// atCreateTkt - atCreate ticket
	_, err = readBytes(reader, atCreateTktSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCreateTkt (size %d): %w", atCreateTktSize, err)
	}

	// atCertifyInfo - atCertify Info
	_, err = readBytes(reader, atCertifyInfoSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifyInfo (size %d): %w", atCertifyInfoSize, err)
	}

	// atCertifiyInfoSignature - atCertify Info signature
	_, err = readBytes(reader, atCertifiyInfoSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifiyInfoSignature (size %d): %w", atCertifiyInfoSignatureSize, err)
	}

	// signingPub - Signing Key public key (IDevID)
	signingPubBytes, err := readBytes(reader, signingPubSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signingPub (size %d): %w", signingPubSize, err)
	}
	signingPubTPMT, err := tpm20.Unmarshal[tpm20.TPMTPublic](signingPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signingPubBytes to TPMTPublic: %w", err)
	}
	result.IDevIDPub = *signingPubTPMT

	// signCertifyInfo - IDevID certification data
	signCertifyInfo, err := readBytes(reader, signCertifyInfoSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signCertifyInfo (size %d): %w", signCertifyInfoSize, err)
	}
	signCertifyInfoTPMS, err := tpm20.Unmarshal[tpm20.TPMSAttest](signCertifyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signCertifyInfo to TPMSAttest: %w", err)
	}
	result.SignCertifyInfo = *signCertifyInfoTPMS

	// signCertifyInfoSignature - Signature of the SignCertifyInfo field by IAK
	signCertifyInfoSignature, err := readBytes(reader, signCertifyInfoSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signCertifyInfoSignature (size %d): %w", signCertifyInfoSignatureSize, err)
	}
	signCertifyInfoSignatureTPMTS, err := tpm20.Unmarshal[tpm20.TPMTSignature](signCertifyInfoSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signCertifyInfoSignature to TPMTSignature: %w", err)
	}
	result.SignCertifyInfoSignature = *signCertifyInfoSignatureTPMTS

	// pad - empty bytes to make the size struct a multiple of 16 bytes
	_, err = readBytes(reader, padSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.pad (size %d): %w", padSize, err)
	}
	log.Infof("padSize: %d", padSize)

	// Final check: ensure no unread bytes in the TCG_CSR_IDEVID_CONTENT block
	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TCG_CSR_IDEVID_CONTENT block after parsing: %d", reader.Len())
	}

	return result, nil
}
