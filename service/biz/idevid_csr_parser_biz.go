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
	"encoding/binary"
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
	SignCertifyInfo          tpm2.TPMSAttest    // IDevID certification data by IAK (TPMS_ATTEST structure)
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

// ParseTCGCSRIDevIDContent parses the TCG_CSR_IDEVID_CONTENT structure from a byte slice
// and returns a TCGCSRIDevIDContents struct.
// Ref: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-Keys-for-Device-Identity-and-Attestation-v1.10r9_pub.pdf#page=71
func ParseTCGCSRIDevIDContent(csrBytes []byte) (*TCGCSRIDevIDContents, error) {
	reader := bytes.NewReader(csrBytes)
	result := &TCGCSRIDevIDContents{}

	// Read the first few fields and the sizes of the fields in the TCG_CSR_IDEVID_CONTENT structure.

	// structVer (4 bytes)
	structVer, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.structVer: %w", err)
	}
	result.StructVer = structVer

	// hashAlgoId (4 bytes)
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
	SignCertifyInfoSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSize: %w", err)
	}

	// SignCertifyInfoSignatureSize (4 bytes)
	SignCertifyInfoSignatureSize, err := readUint32(reader, true)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSignatureSize: %w", err)
	}

	// padSize (4 bytes)
	padSize, err := readUint32(reader, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read TCG_CSR_IDEVID_CONTENT.padSize: %w", err)
	}

	// TODO: gsaloni - Implement the parsing of fields based on their sizes and remove this log.
	log.Infof("TCG_CSR_IDEVID_CONTENT sizes: prodModelSize=%d, prodSerialSize=%d, ekCertSize=%d,"+
		" attestPubSize=%d, signingPubSize=%d, SignCertifyInfoSize=%d, SignCertifyInfoSignatureSize=%d, padSize=%d",
		prodModelSize, prodSerialSize, ekCertSize, attestPubSize, signingPubSize,
		SignCertifyInfoSize, SignCertifyInfoSignatureSize, padSize)
	return result, nil
}
