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
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	log "github.com/golang/glog"

	"github.com/google/go-tpm/tpm2"
)

// TCGCSRIDevIDContents is the contents of the TCG_CSR_IDEVID_CONTENT structure.
type TCGCSRIDevIDContents struct {
	StructVer                uint32             // Version of the TCG_CSR_IDEVID_CONTENT structure
	HashAlgoID               uint32             // TCG algorithm identifier for the hash field
	Hash                     []byte             // Hash of everything that follows in TCG_CSR_IDEVID_CONTENT
	ProdModel                string             // Product Model string
	ProdSerial               string             // Product Serial string
	EKCert                   string             // Endorsement Key Certificate PEM encoded(X.509)
	IAKPub                   tpm2.TPMTPublic    // Attestation Key public key (IAK)(TPMT_PUBLIC structure)
	IDevIDPub                tpm2.TPMTPublic    // Signing Key public key (TPMT_PUBLIC structure)
	SignCertifyInfo          tpm2.TPMSAttest    // IDevID certification data(TPMS_ATTEST structure)
	SignCertifyInfoSignature tpm2.TPMTSignature // Signature of the SignCertifyInfo field (TPMTSignature structure)
}

// readUint32 is a helper function to read a 4-byte Big Endian unsigned integer.
func readUint32(r *bytes.Reader, assertNonZero bool) (uint32, error) {
	var val uint32
	err := binary.Read(r, binary.BigEndian, &val)
	if err != nil {
		return 0, fmt.Errorf("failed to read uint32: %w", err)
	}
	if assertNonZero {
		if val == 0 {
			return 0, fmt.Errorf("read uint32 is zero, expected non-zero")
		}
	} else {
		if val != 0 {
			return 0, fmt.Errorf("read uint32 is non-zero, expected zero")
		}
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

// ParseTCGCSRIDevIDContent parses the TCG_CSR_IDEVID_CONTENT structure from a byte slice
// and returns a TCGCSRIDevIDContents struct.
// Ref: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf#page=71
func ParseTCGCSRIDevIDContent(csrBytes []byte) (*TCGCSRIDevIDContents, error) {
	reader := bytes.NewReader(csrBytes)
	result := &TCGCSRIDevIDContents{}

	// Read the first few fields and the sizes of the fields in the TCG_CSR_IDEVID_CONTENT structure.

	// structVer (4 bytes) - Version of the TCG_CSR_IDEVID_CONTENT structure
	structVer, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.structVer: %w", err)
	}
	result.StructVer = structVer

	// hashAlgoId (4 bytes) - TCG algorithm identifier for the hash field
	hashAlgoID, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.hashAlgoId: %w", err)
	}
	result.HashAlgoID = hashAlgoID

	// hashSize (4 bytes)
	hashSize, err := readUint32(reader, true)
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
	prodModelSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodModelSize: %w", err)
	}

	// prodSerialSize (4 bytes)
	prodSerialSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodSerialSize: %w", err)
	}

	// prodCaDataSize (4 bytes)
	_, err = readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.prodCaDataSize: %w", err)
	}

	// bootEvntLogSize (4 bytes)
	_, err = readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.bootEvntLogSize: %w", err)
	}

	// ekCertSize (4 bytes)
	ekCertSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.ekCertSize: %w", err)
	}

	// attestPubSize (4 bytes)
	attestPubSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.attestPubSize: %w", err)
	}

	// atCreateTktSize (4 bytes)
	_, err = readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCreateTktSize: %w", err)
	}

	// atCertifyInfoSize (4 bytes)
	_, err = readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifyInfoSize: %w", err)
	}

	// atCertifiyInfoSignatureSize (4 bytes)
	_, err = readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.atCertifiyInfoSignatureSize: %w", err)
	}

	// signingPubSize (4 bytes)
	signingPubSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signingPubSize: %w", err)
	}

	// SignCertifyInfoSize (4 bytes)
	signCertifyInfoSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSize: %w", err)
	}

	// SignCertifyInfoSignatureSize (4 bytes)
	signCertifyInfoSignatureSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSignatureSize: %w", err)
	}

	// padSize (4 bytes)
	padSize, err := readUint32(reader, false)
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
	attestPubTPMT, err := tpm2.Unmarshal[tpm2.TPMTPublic](attestPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestPubBytes to TPMTPublic: %w", err)
	}
	result.IAKPub = *attestPubTPMT

	// signingPub - Signing Key public key (IDevID)
	signingPubBytes, err := readBytes(reader, signingPubSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.signingPub (size %d): %w", signingPubSize, err)
	}
	signingPubTPMT, err := tpm2.Unmarshal[tpm2.TPMTPublic](signingPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signingPubBytes to TPMTPublic: %w", err)
	}
	result.IDevIDPub = *signingPubTPMT

	// sgnCertifyInfo - IDevID certification data
	sgnCertifyInfo, err := readBytes(reader, signCertifyInfoSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.sgnCertifyInfo (size %d): %w", signCertifyInfoSize, err)
	}
	log.Infof("sgnCertifyInfo: %x", sgnCertifyInfo)
	sgnCertifyInfoTPMS, err := tpm2.Unmarshal[tpm2.TPMSAttest](sgnCertifyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sgnCertifyInfo to TPMSAttest: %w", err)
	}
	result.SignCertifyInfo = *sgnCertifyInfoTPMS

	// sgnCertifyInfoSignature - Signature of the SignCertifyInfo field by IAK
	sgnCertifyInfoSignature, err := readBytes(reader, signCertifyInfoSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.sgnCertifyInfoSignature (size %d): %w", signCertifyInfoSignatureSize, err)
	}
	sgnCertifyInfoSignatureTPMTS, err := tpm2.Unmarshal[tpm2.TPMTSignature](sgnCertifyInfoSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sgnCertifyInfoSignature to TPMTSignature: %w", err)
	}
	log.Infof("sgnCertifyInfoSignatureTPMTS: %#+v", tpm2.Marshal(sgnCertifyInfoSignatureTPMTS))
	result.SignCertifyInfoSignature = *sgnCertifyInfoSignatureTPMTS

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
