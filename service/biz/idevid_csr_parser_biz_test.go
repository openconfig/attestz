package biz

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type CsrOptions struct {
	StructVer                    *uint32
	HashAlgoID                   *uint32
	Hash                         []byte
	ProdModel                    *string
	ProdSerial                   *string
	EKCert                       *string
	PadSize                      *uint32
	ProdCaDataSize               *uint32
	BootEvntLogSize              *uint32
	AttestPubSize                *uint32
	SigningPubSize               *uint32
	SignCertifyInfoSize          *uint32
	SignCertifyInfoSignatureSize *uint32
	AtCreateTktSize              *uint32
	AtCertifyInfoSize            *uint32
	AtCertifiyInfoSignatureSize  *uint32
}

// Helper function to generate valid csrBytes for testing, this will be useful when adding new fields to the structure
func generateCsrBytes(options CsrOptions) []byte {
	var buffer bytes.Buffer

	// Set default values
	defaultOptions := CsrOptions{
		StructVer:                    ptrUint32(1),
		HashAlgoID:                   ptrUint32(2),
		Hash:                         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		ProdModel:                    ptrString("MyProductModel"),
		ProdSerial:                   ptrString("MyProductSerial"),
		EKCert:                       ptrString("MyEkCert"),
		PadSize:                      ptrUint32(0),
		ProdCaDataSize:               ptrUint32(0),
		BootEvntLogSize:              ptrUint32(0),
		AttestPubSize:                ptrUint32(10),
		SigningPubSize:               ptrUint32(10),
		SignCertifyInfoSize:          ptrUint32(10),
		SignCertifyInfoSignatureSize: ptrUint32(10),
		AtCreateTktSize:              ptrUint32(0),
		AtCertifyInfoSize:            ptrUint32(0),
		AtCertifiyInfoSignatureSize:  ptrUint32(0),
	}

	// Apply options
	if options.StructVer != nil {
		defaultOptions.StructVer = options.StructVer
	}
	if options.HashAlgoID != nil {
		defaultOptions.HashAlgoID = options.HashAlgoID
	}
	if options.Hash != nil {
		defaultOptions.Hash = options.Hash
	}
	if options.ProdModel != nil {
		defaultOptions.ProdModel = options.ProdModel
	}
	if options.ProdSerial != nil {
		defaultOptions.ProdSerial = options.ProdSerial
	}
	if options.EKCert != nil {
		defaultOptions.EKCert = options.EKCert
	}
	if options.PadSize != nil {
		defaultOptions.PadSize = options.PadSize
	}
	if options.ProdCaDataSize != nil {
		defaultOptions.ProdCaDataSize = options.ProdCaDataSize
	}
	if options.BootEvntLogSize != nil {
		defaultOptions.BootEvntLogSize = options.BootEvntLogSize
	}
	if options.AttestPubSize != nil {
		defaultOptions.AttestPubSize = options.AttestPubSize
	}
	if options.SigningPubSize != nil {
		defaultOptions.SigningPubSize = options.SigningPubSize
	}
	if options.SignCertifyInfoSize != nil {
		defaultOptions.SignCertifyInfoSize = options.SignCertifyInfoSize
	}
	if options.SignCertifyInfoSignatureSize != nil {
		defaultOptions.SignCertifyInfoSignatureSize = options.SignCertifyInfoSignatureSize
	}
	if options.AtCreateTktSize != nil {
		defaultOptions.AtCreateTktSize = options.AtCreateTktSize
	}
	if options.AtCertifyInfoSize != nil {
		defaultOptions.AtCertifyInfoSize = options.AtCertifyInfoSize
	}
	if options.AtCertifiyInfoSignatureSize != nil {
		defaultOptions.AtCertifiyInfoSignatureSize = options.AtCertifiyInfoSignatureSize
	}

	// structVer (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.StructVer)
	// hashAlgoID (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.HashAlgoID)
	// hashSize (4 bytes)
	binaryWriteUint32(&buffer, uint32(len(defaultOptions.Hash)))
	// hash (hashSize bytes)
	buffer.Write(defaultOptions.Hash)
	// prodModelSize (4 bytes)
	binaryWriteUint32(&buffer, uint32(len(*defaultOptions.ProdModel)))
	// prodSerialSize (4 bytes)
	binaryWriteUint32(&buffer, uint32(len(*defaultOptions.ProdSerial)))
	// prodCaDataSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.ProdCaDataSize)
	// bootEvntLogSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.BootEvntLogSize)
	// ekCertSize (4 bytes)
	binaryWriteUint32(&buffer, uint32(len(*defaultOptions.EKCert)))
	// attestPubSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.AttestPubSize)
	// atCreateTktSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.AtCreateTktSize)
	// atCertifyInfoSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.AtCertifyInfoSize)
	// atCertifiyInfoSignatureSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.AtCertifiyInfoSignatureSize)
	// signingPubSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.SigningPubSize)
	// SignCertifyInfoSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.SignCertifyInfoSize)
	// SignCertifyInfoSignatureSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.SignCertifyInfoSignatureSize)
	// padSize (4 bytes)
	binaryWriteUint32(&buffer, *defaultOptions.PadSize)
	// prodModel
	buffer.WriteString(*defaultOptions.ProdModel)
	// prodSerial
	buffer.WriteString(*defaultOptions.ProdSerial)
	// ekCert
	buffer.WriteString(*defaultOptions.EKCert)
	// pad
	for i := uint32(0); i < *defaultOptions.PadSize; i++ {
		buffer.WriteByte(0)
	}
	return buffer.Bytes()
}

func binaryWriteUint32(buf *bytes.Buffer, value uint32) {
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		panic(fmt.Sprintf("failed to write uint32: %v", err))
	}
}

func ptrUint32(value uint32) *uint32 {
	return &value
}

func ptrString(value string) *string {
	return &value
}

func TestParseTCGCSRIDevIDContent(t *testing.T) {
	// Define test cases
	tests := []struct {
		name           string
		csrBytes       []byte
		expectedError  error
		expectedResult *TCGCSRIDevIDContents
	}{
		{
			name:          "Valid CSR bytes",
			csrBytes:      generateCsrBytes(CsrOptions{}),
			expectedError: nil,
			expectedResult: &TCGCSRIDevIDContents{
				StructVer:  1,
				HashAlgoID: 2,
				Hash:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
			},
		},
		{
			name:          "prodCaDataSize not zero",
			csrBytes:      generateCsrBytes(CsrOptions{ProdCaDataSize: ptrUint32(1)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.prodCaDataSize: read uint32 is non-zero, expected zero"),
		},
		{
			name:          "bootEvntLogSize not zero",
			csrBytes:      generateCsrBytes(CsrOptions{BootEvntLogSize: ptrUint32(1)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.bootEvntLogSize: read uint32 is non-zero, expected zero"),
		},
		{
			name:          "atCreateTktSize not zero",
			csrBytes:      generateCsrBytes(CsrOptions{AtCreateTktSize: ptrUint32(1)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.atCreateTktSize: read uint32 is non-zero, expected zero"),
		},
		{
			name:          "atCertifyInfoSize not zero",
			csrBytes:      generateCsrBytes(CsrOptions{AtCertifyInfoSize: ptrUint32(1)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.atCertifyInfoSize: read uint32 is non-zero, expected zero"),
		},
		{
			name:          "atCertifiyInfoSignatureSize not zero",
			csrBytes:      generateCsrBytes(CsrOptions{AtCertifiyInfoSignatureSize: ptrUint32(1)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.atCertifiyInfoSignatureSize: read uint32 is non-zero, expected zero"),
		},
		{
			name:          "signingPubSize zero",
			csrBytes:      generateCsrBytes(CsrOptions{SigningPubSize: ptrUint32(0)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.signingPubSize: read uint32 is zero, expected non-zero"),
		},
		{
			name:          "attestPubSize zero",
			csrBytes:      generateCsrBytes(CsrOptions{AttestPubSize: ptrUint32(0)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.attestPubSize: read uint32 is zero, expected non-zero"),
		},
		{
			name:          "SignCertifyInfoSize zero",
			csrBytes:      generateCsrBytes(CsrOptions{SignCertifyInfoSize: ptrUint32(0)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSize: read uint32 is zero, expected non-zero"),
		},
		{
			name:          "SignCertifyInfoSignatureSize zero",
			csrBytes:      generateCsrBytes(CsrOptions{SignCertifyInfoSignatureSize: ptrUint32(0)}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.SignCertifyInfoSignatureSize: read uint32 is zero, expected non-zero"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("test case: %s", tc.name)
			result, err := ParseTCGCSRIDevIDContent(tc.csrBytes)

			if tc.expectedError != nil {
				if err == nil || !cmp.Equal(err.Error(), tc.expectedError.Error()) {
					t.Errorf("ParseTCGCSRIDevIDContent(%v) expected an error: %v, but got: %v", hex.EncodeToString(tc.csrBytes), tc.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTCGCSRIDevIDContent returned an unexpected error: %v", err)
			}

			wantStr := fmt.Sprintf("%#+v", tc.expectedResult)
			gotStr := fmt.Sprintf("%#+v", result)
			if diff := cmp.Diff(wantStr, gotStr); diff != "" {
				t.Errorf("ParseTCGCSRIDevIDContent returned an unexpected result: diff (-want +got):\n%s", diff)
			}
		})
	}
}
