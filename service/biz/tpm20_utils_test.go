package biz

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	tpm20 "github.com/google/go-tpm/tpm2"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"
)

var (
	defaultEkCertDerBytes, defaultEkCertPEM = generateX509Cert()
	defaultCsrOptions                       = CsrOptions{
		StructVer:                   ptrUint32(1),
		HashAlgoID:                  ptrUint32(2),
		Hash:                        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		ProdModel:                   ptrString("MyProductModel"),
		ProdSerial:                  ptrString("MyProductSerial"),
		EKCert:                      defaultEkCertDerBytes,
		PadSize:                     ptrUint32(0),
		ProdCaDataSize:              ptrUint32(0),
		BootEvntLogSize:             ptrUint32(0),
		AttestPub:                   &validTPMTPublic,
		SigningPub:                  &validTPMTPublic,
		SignCertifyInfo:             &validTPMSAttest,
		SignCertifyInfoSignature:    &validTPMTSignature,
		AtCreateTktSize:             ptrUint32(0),
		AtCertifyInfoSize:           ptrUint32(0),
		AtCertifiyInfoSignatureSize: ptrUint32(0),
	}
	invalidBytes = []byte("invalid-bytes")
	validCSR     = &TCGCSRIDevIDContents{
		StructVer:                *defaultCsrOptions.StructVer,
		HashAlgoID:               *defaultCsrOptions.HashAlgoID,
		Hash:                     defaultCsrOptions.Hash,
		ProdModel:                *defaultCsrOptions.ProdModel,
		ProdSerial:               *defaultCsrOptions.ProdSerial,
		EKCert:                   defaultEkCertPEM,
		IAKPub:                   *defaultCsrOptions.AttestPub,
		IDevIDPub:                *defaultCsrOptions.SigningPub,
		SignCertifyInfo:          *defaultCsrOptions.SignCertifyInfo,
		SignCertifyInfoSignature: *defaultCsrOptions.SignCertifyInfoSignature,
	}
)

type CsrOptions struct {
	StructVer                       *uint32
	HashAlgoID                      *uint32
	Hash                            []byte
	ProdModel                       *string
	ProdSerial                      *string
	EKCert                          []byte
	PadSize                         *uint32
	ProdCaDataSize                  *uint32
	BootEvntLogSize                 *uint32
	AttestPub                       *tpm20.TPMTPublic
	AttestPubSize                   *uint32
	SigningPub                      *tpm20.TPMTPublic
	SigningPubSize                  *uint32
	SignCertifyInfo                 *tpm20.TPMSAttest
	SignCertifyInfoSize             *uint32
	SignCertifyInfoSignature        *tpm20.TPMTSignature
	SignCertifyInfoSignatureSize    *uint32
	AtCreateTktSize                 *uint32
	AtCertifyInfoSize               *uint32
	AtCertifiyInfoSignatureSize     *uint32
	InvalidAttestPub                bool
	InvalidSigningPub               bool
	InvalidSignCertifyInfo          bool
	InvalidSignCertifyInfoSignature bool
	AddExtraBytesToEnd              bool
}

func TestVerifyTPMTPublicAttributes_Success(t *testing.T) {
	// Base attributes
	baseAttributes := tpm20.TPMAObject{
		FixedTPM:            true,
		Restricted:          true,
		SensitiveDataOrigin: true,
		SignEncrypt:         true,
		Decrypt:             false,
		FixedParent:         true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
	}

	// Public key with base attributes
	pubKeyWithBaseAttributes := tpm20.TPMTPublic{
		ObjectAttributes: baseAttributes,
	}

	if err := verifyTPMTPublicAttributes(pubKeyWithBaseAttributes, baseAttributes); err != nil {
		t.Errorf("verifyTPMTPublicAttributes() returned an unexpected error: %v", err)
	}
}

func TestVerifyTPMTPublicAttributes_Failure(t *testing.T) {
	// Base attributes
	baseAttributes := tpm20.TPMAObject{
		FixedTPM:            true,
		Restricted:          true,
		SensitiveDataOrigin: true,
		SignEncrypt:         true,
		Decrypt:             false,
		FixedParent:         true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
	}

	// Public key with base attributes
	pubKeyWithBaseAttributes := tpm20.TPMTPublic{
		ObjectAttributes: baseAttributes,
	}

	// Test cases
	tests := []struct {
		name     string
		pubKey   tpm20.TPMTPublic
		expected tpm20.TPMAObject
	}{
		{
			name: "FixedTPM mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.FixedTPM = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "Restricted mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.Restricted = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "SensitiveDataOrigin mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.SensitiveDataOrigin = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "SignEncrypt mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.SignEncrypt = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "Decrypt mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.Decrypt = true
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "FixedParent mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.FixedParent = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "UserWithAuth mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.UserWithAuth = false
				return p
			}(),
			expected: baseAttributes,
		},
		{
			name: "AdminWithPolicy mismatch",
			pubKey: func() tpm20.TPMTPublic {
				p := pubKeyWithBaseAttributes
				p.ObjectAttributes.AdminWithPolicy = false
				return p
			}(),
			expected: baseAttributes,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyTPMTPublicAttributes(tc.pubKey, tc.expected)
			if err == nil {
				t.Error("verifyTPMTPublicAttributes() expected an error, but got nil")
			}
			if !errors.Is(err, ErrInvalidPubKeyAttributes) {
				t.Errorf("verifyTPMTPublicAttributes() expected error to wrap ErrInvalidPubKeyAttributes, but got %v", err)
			}
		})
	}
}

func TestVerifyIAKAttributes_Success(t *testing.T) {
	u := DefaultTPM20Utils{}

	validIAKPub := validTPMTPublic
	validIAKPub.ObjectAttributes = tpm20.TPMAObject{
		FixedTPM:            true,
		Restricted:          true,
		SensitiveDataOrigin: true,
		SignEncrypt:         true,
		Decrypt:             false,
		FixedParent:         true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
	}
	validIAKPub.NameAlg = tpm20.TPMAlgSHA256
	validIAKPubBytes := tpm20.Marshal(validIAKPub)

	pubWithSHA384 := validIAKPub
	pubWithSHA384.NameAlg = tpm20.TPMAlgSHA384
	pubWithSHA384Bytes := tpm20.Marshal(pubWithSHA384)

	tests := []struct {
		name   string
		iakPub []byte
		want   *tpm20.TPMTPublic
	}{
		{
			name:   "Success",
			iakPub: validIAKPubBytes,
			want:   &validIAKPub,
		},
		{
			name:   "Success SHA384",
			iakPub: pubWithSHA384Bytes,
			want:   &pubWithSHA384,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := u.VerifyIAKAttributes(tc.iakPub)
			if err != nil {
				t.Errorf("VerifyIAKAttributes() returned an unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(tpm20.TPMTPublic{}, tpm20.TPMAObject{}, tpm20.TPM2BDigest{}, tpm20.TPMUPublicParms{}, tpm20.TPMUPublicID{})); diff != "" {
				t.Errorf("VerifyIAKAttributes() returned an unexpected result: diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVerifyIAKAttributes_Failure(t *testing.T) {
	u := DefaultTPM20Utils{}

	validIAKPub := validTPMTPublic
	validIAKPub.ObjectAttributes = tpm20.TPMAObject{
		FixedTPM:            true,
		Restricted:          true,
		SensitiveDataOrigin: true,
		SignEncrypt:         true,
		Decrypt:             false,
		FixedParent:         true,
		UserWithAuth:        true,
		AdminWithPolicy:     true,
	}
	validIAKPub.NameAlg = tpm20.TPMAlgSHA256

	invalidUnmarshalBytes := []byte("invalid bytes")

	pubWithBadAttr := validIAKPub
	pubWithBadAttr.ObjectAttributes.FixedTPM = false
	pubWithBadAttrBytes := tpm20.Marshal(pubWithBadAttr)

	pubWithBadUserWithAuth := validIAKPub
	pubWithBadUserWithAuth.ObjectAttributes.UserWithAuth = false
	pubWithBadUserWithAuthBytes := tpm20.Marshal(pubWithBadUserWithAuth)

	pubWithBadAdminWithPolicy := validIAKPub
	pubWithBadAdminWithPolicy.ObjectAttributes.AdminWithPolicy = false
	pubWithBadAdminWithPolicyBytes := tpm20.Marshal(pubWithBadAdminWithPolicy)

	pubWithBadNameAlg := validIAKPub
	pubWithBadNameAlg.NameAlg = tpm20.TPMAlgSHA1
	pubWithBadNameAlgBytes := tpm20.Marshal(pubWithBadNameAlg)

	tests := []struct {
		name   string
		iakPub []byte
	}{
		{
			name:   "Unmarshal error",
			iakPub: invalidUnmarshalBytes,
		},
		{
			name:   "Attribute mismatch",
			iakPub: pubWithBadAttrBytes,
		},
		{
			name:   "UserWithAuth mismatch",
			iakPub: pubWithBadUserWithAuthBytes,
		},
		{
			name:   "AdminWithPolicy mismatch",
			iakPub: pubWithBadAdminWithPolicyBytes,
		},
		{
			name:   "Invalid NameAlg",
			iakPub: pubWithBadNameAlgBytes,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.VerifyIAKAttributes(tc.iakPub)
			if err == nil {
				t.Error("VerifyIAKAttributes() expected an error, but got nil")
			}
		})
	}
}

func TestVerifyCertifyInfo(t *testing.T) {
	u := DefaultTPM20Utils{}
	keyName, err := tpm20.ObjectName(&validTPMTPublic)
	if err != nil {
		t.Fatalf("tpm20.ObjectName failed: %v", err)
	}

	attestBase := tpm20.TPMSAttest{
		Magic:           tpm20.TPMGeneratedValue,
		Type:            tpm20.TPMSTAttestCertify,
		QualifiedSigner: tpm20.TPM2BName{Buffer: []byte{0x01}},
		ExtraData:       tpm20.TPM2BData{Buffer: []byte{}},
		ClockInfo:       tpm20.TPMSClockInfo{Clock: 1, ResetCount: 1, RestartCount: 1, Safe: false},
		FirmwareVersion: 1,
	}

	attestWithGoodName := attestBase
	attestWithGoodName.Attested = tpm20.NewTPMUAttest(tpm20.TPMSTAttestCertify, &tpm20.TPMSCertifyInfo{
		Name:          *keyName,
		QualifiedName: tpm20.TPM2BName{Buffer: []byte{0x0a, 0x0b}},
	})

	attestWithBadMagic := attestWithGoodName
	attestWithBadMagic.Magic = 0x1234
	attestWithBadMagic.Attested = tpm20.NewTPMUAttest(tpm20.TPMSTAttestCertify, &tpm20.TPMSCertifyInfo{
		Name:          *keyName,
		QualifiedName: tpm20.TPM2BName{Buffer: []byte{0x0a, 0x0b}},
	})

	attestWithBadType := attestWithGoodName
	attestWithBadType.Type = tpm20.TPMSTAttestCreation
	attestWithBadType.Attested = tpm20.NewTPMUAttest(tpm20.TPMSTAttestCreation, &tpm20.TPMSCreationInfo{})

	attestWithBadName := attestBase
	attestWithBadName.Attested = tpm20.NewTPMUAttest(tpm20.TPMSTAttestCertify, &tpm20.TPMSCertifyInfo{
		Name:          tpm20.TPM2BName{Buffer: []byte{0x01}},
		QualifiedName: tpm20.TPM2BName{Buffer: []byte{0x02}},
	})

	attestWithSameNameAndQN := attestBase
	attestWithSameNameAndQN.Attested = tpm20.NewTPMUAttest(tpm20.TPMSTAttestCertify, &tpm20.TPMSCertifyInfo{
		Name:          *keyName,
		QualifiedName: *keyName,
	})

	tests := []struct {
		name      string
		attest    *tpm20.TPMSAttest
		pub       *tpm20.TPMTPublic
		wantError error
	}{
		{
			name:      "Success",
			attest:    &attestWithGoodName,
			pub:       &validTPMTPublic,
			wantError: nil,
		},
		{
			name:      "Invalid Magic",
			attest:    &attestWithBadMagic,
			pub:       &validTPMTPublic,
			wantError: ErrInvalidCertifyInfo,
		},
		{
			name:      "Invalid Type",
			attest:    &attestWithBadType,
			pub:       &validTPMTPublic,
			wantError: ErrInvalidCertifyInfo,
		},
		{
			name:      "Wrong Name in CertifyInfo",
			attest:    &attestWithBadName,
			pub:       &validTPMTPublic,
			wantError: ErrCertifiedWrongName,
		},
		{
			name:      "Name same as QualifiedName in CertifyInfo",
			attest:    &attestWithSameNameAndQN,
			pub:       &validTPMTPublic,
			wantError: ErrCertifiedWrongName,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := u.VerifyCertifyInfo(tc.attest, tc.pub)
			if !errors.Is(err, tc.wantError) {
				t.Errorf("VerifyCertifyInfo() returned error %v, want %v", err, tc.wantError)
			}
		})
	}
}

func generateX509Cert() ([]byte, string) {
	// Create a self-signed certificate for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Google"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	return derBytes, string(pem.EncodeToMemory(block))
}

// Helper function to generate valid csrBytes for testing, this will be useful when adding new fields to the structure
func generateCsrBytes(options CsrOptions) []byte {
	var buffer bytes.Buffer

	// Set default values
	defaultOptions := defaultCsrOptions

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
	if options.AttestPub != nil {
		defaultOptions.AttestPub = options.AttestPub
	}
	var attestPubBytes []byte
	if options.InvalidAttestPub {
		attestPubBytes = invalidBytes
	} else {
		attestPubBytes = tpm20.Marshal(*defaultOptions.AttestPub)
	}
	if options.AttestPubSize != nil {
		defaultOptions.AttestPubSize = options.AttestPubSize
	} else {
		defaultOptions.AttestPubSize = ptrUint32(uint32(len(attestPubBytes)))
	}
	if options.SigningPub != nil {
		defaultOptions.SigningPub = options.SigningPub
	}
	var signingPubBytes []byte
	if options.InvalidSigningPub {
		signingPubBytes = invalidBytes
	} else {
		signingPubBytes = tpm20.Marshal(*defaultOptions.SigningPub)
	}
	if options.SigningPubSize != nil {
		defaultOptions.SigningPubSize = options.SigningPubSize
	} else {
		defaultOptions.SigningPubSize = ptrUint32(uint32(len(signingPubBytes)))
	}
	if options.SignCertifyInfo != nil {
		defaultOptions.SignCertifyInfo = options.SignCertifyInfo
	}
	var signCertifyInfoBytes []byte
	if options.InvalidSignCertifyInfo {
		signCertifyInfoBytes = invalidBytes
	} else {
		signCertifyInfoBytes = tpm20.Marshal(*defaultOptions.SignCertifyInfo)
	}
	if options.SignCertifyInfoSize != nil {
		defaultOptions.SignCertifyInfoSize = options.SignCertifyInfoSize
	} else {
		defaultOptions.SignCertifyInfoSize = ptrUint32(uint32(len(signCertifyInfoBytes)))
	}
	if options.SignCertifyInfoSignature != nil {
		defaultOptions.SignCertifyInfoSignature = options.SignCertifyInfoSignature
	}
	var signCertifyInfoSignatureBytes []byte
	if options.InvalidSignCertifyInfoSignature {
		signCertifyInfoSignatureBytes = invalidBytes
	} else {
		signCertifyInfoSignatureBytes = tpm20.Marshal(*defaultOptions.SignCertifyInfoSignature)
	}
	if options.SignCertifyInfoSignatureSize != nil {
		defaultOptions.SignCertifyInfoSignatureSize = options.SignCertifyInfoSignatureSize
	} else {
		defaultOptions.SignCertifyInfoSignatureSize = ptrUint32(uint32(len(signCertifyInfoSignatureBytes)))
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
	binaryWriteUint32(&buffer, uint32(len(defaultOptions.EKCert)))
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
	// prodCa + BootEventLog bytes
	for i := uint32(0); i < *defaultOptions.ProdCaDataSize+*defaultOptions.BootEvntLogSize; i++ {
		buffer.WriteByte(0)
	}
	// ekCert
	buffer.Write(defaultOptions.EKCert)
	// attestPub
	buffer.Write(attestPubBytes)
	// atCreateTkt + atCertifyInfo + atCertifyInfoSignature bytes
	for i := uint32(0); i < *defaultOptions.AtCreateTktSize+*defaultOptions.AtCertifyInfoSize+*defaultOptions.AtCertifiyInfoSignatureSize; i++ {
		buffer.WriteByte(0)
	}
	// signingPub
	buffer.Write(signingPubBytes)
	// signCertifyInfoSize
	buffer.Write(signCertifyInfoBytes)
	// signCertifyInfoSizeSignature
	buffer.Write(signCertifyInfoSignatureBytes)
	// pad
	for i := uint32(0); i < *defaultOptions.PadSize; i++ {
		buffer.WriteByte(0)
	}
	// extra bytes
	if options.AddExtraBytesToEnd {
		buffer.Write(invalidBytes)
	}
	return buffer.Bytes()
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
			name:           "Valid CSR bytes: zero pad size",
			csrBytes:       generateCsrBytes(CsrOptions{}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "Valid CSR bytes: non-zero pad size",
			csrBytes:       generateCsrBytes(CsrOptions{PadSize: ptrUint32(12)}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "prodCaDataSize not zero",
			csrBytes:       generateCsrBytes(CsrOptions{ProdCaDataSize: ptrUint32(1)}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "bootEvntLogSize not zero",
			csrBytes:       generateCsrBytes(CsrOptions{BootEvntLogSize: ptrUint32(2)}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "atCreateTktSize not zero",
			csrBytes:       generateCsrBytes(CsrOptions{AtCreateTktSize: ptrUint32(3)}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "atCertifyInfoSize not zero",
			csrBytes:       generateCsrBytes(CsrOptions{AtCertifyInfoSize: ptrUint32(4)}),
			expectedError:  nil,
			expectedResult: validCSR,
		},
		{
			name:           "atCertifiyInfoSignatureSize not zero",
			csrBytes:       generateCsrBytes(CsrOptions{AtCertifiyInfoSignatureSize: ptrUint32(5)}),
			expectedError:  nil,
			expectedResult: validCSR,
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
		{
			name: "attestPubSize too large",
			csrBytes: generateCsrBytes(CsrOptions{
				AttestPubSize: ptrUint32(2000),
			}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.attestPub"),
		},
		{
			name: "signingPubSize too large",
			csrBytes: generateCsrBytes(CsrOptions{
				SigningPubSize: ptrUint32(2000),
			}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.signingPub"),
		},
		{
			name: "signCertifyInfoSize too large",
			csrBytes: generateCsrBytes(CsrOptions{
				SignCertifyInfoSize: ptrUint32(2000),
			}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.signCertifyInfo"),
		},
		{
			name: "signCertifyInfoSignatureSize too large",
			csrBytes: generateCsrBytes(CsrOptions{
				SignCertifyInfoSignatureSize: ptrUint32(2000),
			}),
			expectedError: errors.New("failed to read TCG_CSR_IDEVID_CONTENT.signCertifyInfoSignature"),
		},
		{
			name:          "Invalid EK Cert",
			csrBytes:      generateCsrBytes(CsrOptions{EKCert: []byte("invalid-ek-cert")}),
			expectedError: errors.New("failed to convert EK Cert to PEM"),
		},
		{
			name:          "Invalid Attest Pub Bytes",
			csrBytes:      generateCsrBytes(CsrOptions{InvalidAttestPub: true}),
			expectedError: errors.New("failed to unmarshal attestPubBytes to TPMTPublic"),
		},
		{
			name:          "Invalid Signing Pub Bytes",
			csrBytes:      generateCsrBytes(CsrOptions{InvalidSigningPub: true}),
			expectedError: errors.New("failed to unmarshal signingPubBytes to TPMTPublic"),
		},
		{
			name:          "Invalid Sign Certify Info Bytes",
			csrBytes:      generateCsrBytes(CsrOptions{InvalidSignCertifyInfo: true}),
			expectedError: errors.New("failed to unmarshal signCertifyInfo to TPMSAttest"),
		},
		{
			name:          "Invalid Sign Certify Signature Info Bytes",
			csrBytes:      generateCsrBytes(CsrOptions{InvalidSignCertifyInfoSignature: true}),
			expectedError: errors.New("failed to unmarshal signCertifyInfoSignature to TPMTSignature"),
		},
		{
			name:          "Invalid Extra bytes at the end of CSR",
			csrBytes:      generateCsrBytes(CsrOptions{AddExtraBytesToEnd: true}),
			expectedError: errors.New("leftover bytes in TCG_CSR_IDEVID_CONTENT block after parsing"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := DefaultTPM20Utils{}
			result, err := u.ParseTCGCSRIDevIDContent(tc.csrBytes)

			if tc.expectedError != nil {
				if err == nil || !strings.Contains(err.Error(), tc.expectedError.Error()) {
					t.Errorf("ParseTCGCSRIDevIDContent expected an error: %v, but got: %v", tc.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTCGCSRIDevIDContent returned an unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.expectedResult, result, cmpopts.IgnoreUnexported(tpm20.TPMTPublic{}, tpm20.TPMSAttest{}, tpm20.TPMTSignature{}, tpm20.TPMAObject{}, tpm20.TPM2BDigest{}, tpm20.TPMUPublicParms{}, tpm20.TPMUPublicID{}, tpm20.TPM2BName{}, tpm20.TPM2BData{}, tpm20.TPMSClockInfo{}, tpm20.TPMUAttest{}, tpm20.TPMUSignature{})); diff != "" {
				t.Errorf("ParseTCGCSRIDevIDContent returned an unexpected result: diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateRSAPublicKey_Success(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key for testing: %v", err)
	}
	if err = ValidateRSAPublicKey(&privKey.PublicKey); err != nil {
		t.Errorf("TestValidateRSAPublicKey_Success() failed: got error: %v", err)
	}
}

func TestValidateRSAPublicKey_Failure(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key for testing: %v", err)
	}
	tests := []struct {
		name    string
		pub     *rsa.PublicKey
		wantErr string
	}{
		{
			name:    "Nil Input",
			wantErr: "RSA public key cannot be empty",
		},
		{
			name: "Nil Modulus",
			pub: &rsa.PublicKey{
				N: nil,
				E: 65537,
			},
			wantErr: "invalid RSA public key modulus",
		},
		{
			name: "Invalid Bits",
			pub: &rsa.PublicKey{
				N: big.NewInt(123456),
				E: 65537,
			},
			wantErr: "invalid RSA public key bits",
		},
		{
			name: "Even Exponent",
			pub: &rsa.PublicKey{
				N: privKey.N,
				E: 2,
			},
			wantErr: "invalid RSA public key exponent",
		},
		{
			name: "Overflown Exponent",
			pub: &rsa.PublicKey{
				N: privKey.N,
				E: 1<<31 + 1,
			},
			wantErr: "RSA public key exponent is too large",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRSAPublicKey(tc.pub); !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("TestValidateRSAPublicKey_Failure() failed: expected error: %v, but got error: %v", tc.wantErr, err)
			}
		})
	}
}

func TestGenerateRestrictedHMACKey(t *testing.T) {
	u := &DefaultTPM20Utils{}
	pub, priv, err := u.GenerateRestrictedHMACKey()
	if err != nil {
		t.Fatalf("TestGenerateRestrictedHMACKey() failed to generate HMAC key: %v", err)
	}
	hash, err := pub.Unique.KeyedHash()
	if err != nil {
		t.Fatalf("TestGenerateRestrictedHMACKey() failed to get KeyedHash: %v", err)
	}
	got := hash.Buffer
	bits, err := priv.Sensitive.Bits()
	if err != nil {
		t.Fatalf("TestGenerateRestrictedHMACKey() failed to get Sensitive Bits: %v", err)
	}
	sha := sha256.New()
	sha.Write(append(priv.SeedValue.Buffer, bits.Buffer...))
	want := sha.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("TestGenerateRestrictedHMACKey() failed: got %v, want %v", got, want)
	}
}

func TestRSAEKPublicKeyToTPMTPublic_Success(t *testing.T) {
	u := &DefaultTPM20Utils{}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key for testing: %v", err)
	}
	input := &rsa.PublicKey{
		N: privKey.N,
		E: 65537,
	}
	want := &tpm20.TPMTPublic{
		Type:    tpm20.TPMAlgRSA,
		NameAlg: tpm20.TPMAlgSHA256,
		ObjectAttributes: tpm20.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         false,
			AdminWithPolicy:      true,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm20.TPM2BDigest{
			Buffer: []byte{
				// TPM2_PolicySecret(RH_ENDORSEMENT)
				0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
				0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
				0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
				0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			},
		},
		Parameters: tpm20.NewTPMUPublicParms(
			tpm20.TPMAlgRSA,
			&tpm20.TPMSRSAParms{
				Symmetric: tpm20.TPMTSymDefObject{
					Algorithm: tpm20.TPMAlgAES,
					KeyBits: tpm20.NewTPMUSymKeyBits(
						tpm20.TPMAlgAES,
						tpm20.TPMKeyBits(128),
					),
					Mode: tpm20.NewTPMUSymMode(
						tpm20.TPMAlgAES,
						tpm20.TPMAlgCFB,
					),
				},
				KeyBits:  2048,
				Exponent: 0,
			},
		),
		Unique: tpm20.NewTPMUPublicID(
			tpm20.TPMAlgRSA,
			&tpm20.TPM2BPublicKeyRSA{
				Buffer: input.N.Bytes(),
			},
		),
	}

	got, err := u.RSAEKPublicKeyToTPMTPublic(input)
	if err != nil {
		t.Errorf("TestRSAEKPublicKeyToTPMTPublic_Success() failed, got error %v", err)
		return
	}
	if diff := cmp.Diff(tpm20.Marshal(want), tpm20.Marshal(got)); diff != "" {
		t.Errorf("TestRSAEKPublicKeyToTPMTPublic_Success() returned an unexpected result: want: %#v, got: %#v, diff (-want +got):\n%s", want, got, diff)
	}
}

func TestRSAEKPublicKeyToTPMTPublic_Failure(t *testing.T) {
	u := &DefaultTPM20Utils{}
	_, err := u.RSAEKPublicKeyToTPMTPublic(nil)
	if !errors.Is(err, ErrInputNil) {
		t.Errorf("TestRSAEKPublicKeyToTPMTPublic_Failure() failed, want error: %v, got error %v", ErrInputNil, err)
	}
}

func TestWrapHMACKeytoRSAPublicKey_Success(t *testing.T) {
	u := &DefaultTPM20Utils{}
	hmacPub, hmacSensitive, err := u.GenerateRestrictedHMACKey()
	if err != nil {
		t.Fatalf("TestWrapHMACKeytoRSAPublicKey_Success() failed to generate HMAC key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("TestWrapHMACKeytoRSAPublicKey_Success() failed to generate RSA key: %v", err)
	}

	if duplicate, inSymSeed, err := u.WrapHMACKeytoRSAPublicKey(&rsaKey.PublicKey, hmacPub, hmacSensitive); err != nil {
		t.Errorf("TestWrapHMACKeytoRSAPublicKey_Success() failed, got error: %v", err)
	} else if len(duplicate) == 0 {
		t.Errorf("TestWrapHMACKeytoRSAPublicKey_Success() failed, got empty duplicate")
	} else if len(inSymSeed) == 0 {
		t.Errorf("TestWrapHMACKeytoRSAPublicKey_Success() failed, got empty inSymSeed")
	}
}

func TestWrapHMACKeytoRSAPublicKey_Failure(t *testing.T) {
	u := &DefaultTPM20Utils{}
	hmacPub, hmacSensitive, err := u.GenerateRestrictedHMACKey()
	if err != nil {
		t.Fatalf("TestWrapHMACKeytoRSAPublicKey_Failure() failed to generate HMAC key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("TestWrapHMACKeytoRSAPublicKey_Failure() failed to generate RSA key: %v", err)
	}

	testCases := []struct {
		name    string
		ek      *rsa.PublicKey
		pub     *tpm20.TPMTPublic
		priv    *tpm20.TPMTSensitive
		wantErr error
	}{
		{
			name:    "Nil HMAC Pub",
			ek:      &rsaKey.PublicKey,
			priv:    hmacSensitive,
			wantErr: ErrInputNil,
		},
		{
			name:    "Nil HMAC Priv",
			ek:      &rsaKey.PublicKey,
			pub:     hmacPub,
			wantErr: ErrInputNil,
		},
		{
			name:    "Nil EK",
			pub:     hmacPub,
			priv:    hmacSensitive,
			wantErr: ErrInputNil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := u.WrapHMACKeytoRSAPublicKey(tc.ek, tc.pub, tc.priv); !errors.Is(err, tc.wantErr) {
				t.Errorf("TestWrapHMACKeytoRSAPublicKey_Failure() failed, want error %v, got error %v", tc.wantErr, err)
			}
		})
	}
}

func TestVerifyHMAC(t *testing.T) {
	u := &DefaultTPM20Utils{}
	// The following test vectors are true values generated by using a TPM hardware simulator.
	// Generation code reference: https://github.com/TrustedComputingGroup/tpm-fw-attestation-reference-code/blob/main/go/pkg/host/host.go
	message := []byte{0xFF, 0x54, 0x43, 0x47, 0x80, 0x17, 0x00, 0x22, 0x00, 0x0B, 0xCF, 0x1E, 0xC6, 0x7A, 0xE7, 0x6A, 0x85, 0xAD, 0x78, 0xDC, 0xE2, 0x84, 0x3F, 0x9A, 0x2B, 0x37, 0x25, 0x23, 0xCA, 0x27, 0x1B, 0x09, 0xE9, 0x72, 0x24, 0x33, 0x16, 0x05, 0x35, 0x7B, 0xD0, 0xCB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x17, 0x06, 0x19, 0x00, 0x16, 0x36, 0x36, 0x00, 0x22, 0x00, 0x0B, 0x01, 0x01, 0x3B, 0xBF, 0x20, 0xFB, 0xAB, 0x85, 0x80, 0x0C, 0xCA, 0xB6, 0xBB, 0x6A, 0x2B, 0x07, 0xA9, 0x01, 0x52, 0x26, 0x48, 0x77, 0xD3, 0x85, 0xB4, 0x2E, 0xF0, 0x2C, 0x34, 0x70, 0xA6, 0x75, 0x00, 0x22, 0x00, 0x0B, 0xCF, 0x1E, 0xC6, 0x7A, 0xE7, 0x6A, 0x85, 0xAD, 0x78, 0xDC, 0xE2, 0x84, 0x3F, 0x9A, 0x2B, 0x37, 0x25, 0x23, 0xCA, 0x27, 0x1B, 0x09, 0xE9, 0x72, 0x24, 0x33, 0x16, 0x05, 0x35, 0x7B, 0xD0, 0xCB}
	signature := []byte{0x00, 0x05, 0x00, 0x0B, 0x39, 0x24, 0x94, 0x25, 0x51, 0x21, 0xA8, 0x57, 0x24, 0x94, 0x7E, 0x04, 0x4D, 0xAF, 0x7A, 0x23, 0x45, 0x40, 0x2A, 0xD2, 0xDD, 0x4E, 0x4B, 0x5F, 0x63, 0x30, 0x5B, 0x34, 0xA2, 0x10, 0xAD, 0x57}
	hmacKey := []byte{0x08, 0x99, 0x71, 0xA1, 0x94, 0xAA, 0x90, 0x6C, 0xF9, 0x0C, 0xE2, 0xEE, 0xE4, 0x3C, 0x9B, 0xD7, 0x91, 0xB4, 0x63, 0x58, 0x39, 0xED, 0xCE, 0x5A, 0xBB, 0x6E, 0x78, 0xDA, 0x1C, 0x4F, 0xE0, 0x97}
	sensitive := &tpm20.TPMTSensitive{
		SensitiveType: tpm20.TPMAlgKeyedHash,
		Sensitive: tpm20.NewTPMUSensitiveComposite(tpm20.TPMAlgKeyedHash, &tpm20.TPM2BSensitiveData{
			Buffer: hmacKey,
		}),
	}
	sensitiveIncorrect := &tpm20.TPMTSensitive{
		SensitiveType: tpm20.TPMAlgKeyedHash,
		Sensitive: tpm20.NewTPMUSensitiveComposite(tpm20.TPMAlgKeyedHash, &tpm20.TPM2BSensitiveData{
			Buffer: append(hmacKey[10:], hmacKey[:10]...),
		}),
	}

	successTests := []struct {
		name      string
		message   []byte
		signature []byte
		sensitive *tpm20.TPMTSensitive
	}{
		{
			name:      "HMAC Match",
			message:   message,
			signature: signature,
			sensitive: sensitive,
		},
	}
	for _, tc := range successTests {
		t.Run(tc.name, func(t *testing.T) {
			if err := u.VerifyHMAC(tc.message, tc.signature, tc.sensitive); err != nil {
				t.Errorf("TestVerifyHMAC() returned an unexpected error %v", err)
			}
		})
	}

	failureTests := []struct {
		name      string
		message   []byte
		signature []byte
		sensitive *tpm20.TPMTSensitive
		wantErr   error
	}{
		{
			name:      "Nil Sensitive",
			message:   message,
			signature: signature,
			wantErr:   ErrInputNil,
		},
		{
			name:      "Nil Message",
			signature: signature,
			sensitive: sensitive,
			wantErr:   ErrInputNil,
		},
		{
			name:      "Nil Signature",
			message:   message,
			sensitive: sensitive,
			wantErr:   ErrInputNil,
		},
		{
			name:      "HMAC Not Match",
			message:   message,
			signature: signature,
			sensitive: sensitiveIncorrect,
			wantErr:   ErrHMACNotMatch,
		},
	}
	for _, tc := range failureTests {
		t.Run(tc.name, func(t *testing.T) {
			if err := u.VerifyHMAC(tc.message, tc.signature, tc.sensitive); !errors.Is(err, tc.wantErr) {
				t.Errorf("TestVerifyHMAC() failed, want error %v, got error %v", tc.wantErr, err)
			}
		})
	}
}

func TestVerifyIdevidAttributes(t *testing.T) {
	u := DefaultTPM20Utils{}

	// Base for a valid IDevID public key.
	validIdevidPub := tpm20.TPMTPublic{
		Type:    tpm20.TPMAlgECC,
		NameAlg: tpm20.TPMAlgSHA384,
		ObjectAttributes: tpm20.TPMAObject{
			FixedTPM:            true,
			Restricted:          false,
			SensitiveDataOrigin: true,
			SignEncrypt:         true,
			Decrypt:             false,
			FixedParent:         true,
			UserWithAuth:        true,
			AdminWithPolicy:     true,
		},
		Parameters: tpm20.NewTPMUPublicParms(tpm20.TPMAlgECC, &tpm20.TPMSECCParms{
			Scheme: tpm20.TPMTECCScheme{
				Scheme: tpm20.TPMAlgECDSA,
			},
			CurveID: tpm20.TPMECCNistP384,
		}),
	}

	successTests := []struct {
		name        string
		idevidPub   *tpm20.TPMTPublic
		keyTemplate epb.KeyTemplate
	}{
		{
			name:        "Success ECC P384",
			idevidPub:   &validIdevidPub,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
		},
	}

	for _, tc := range successTests {
		t.Run(tc.name, func(t *testing.T) {
			err := u.VerifyIdevidAttributes(tc.idevidPub, tc.keyTemplate)
			if err != nil {
				t.Errorf("VerifyIDevIDAttributes() returned an unexpected error: %v", err)
			}
		})
	}

	// Make copies and modify for failure cases
	pubWithBadAttr := validIdevidPub
	pubWithBadAttr.ObjectAttributes.Restricted = true // Should be false for IDevID

	pubWithBadType := validIdevidPub
	pubWithBadType.Type = tpm20.TPMAlgRSA

	pubWithBadNameAlg := validIdevidPub
	pubWithBadNameAlg.NameAlg = tpm20.TPMAlgSHA256

	pubWithBadCurve := validIdevidPub
	p, err := pubWithBadCurve.Parameters.ECCDetail()
	if err != nil {
		panic(err)
	}
	newP := *p
	newP.CurveID = tpm20.TPMECCNistP256 // Wrong curve
	pubWithBadCurve.Parameters = tpm20.NewTPMUPublicParms(tpm20.TPMAlgECC, &newP)

	pubWithBadScheme := validIdevidPub
	p, err = pubWithBadScheme.Parameters.ECCDetail()
	if err != nil {
		panic(err)
	}
	newP2 := *p
	newP2.Scheme.Scheme = tpm20.TPMAlgECDAA // Wrong scheme
	pubWithBadScheme.Parameters = tpm20.NewTPMUPublicParms(tpm20.TPMAlgECC, &newP2)

	pubWithMismatchedParams := validIdevidPub
	pubWithMismatchedParams.Type = tpm20.TPMAlgECC
	pubWithMismatchedParams.Parameters = tpm20.NewTPMUPublicParms(tpm20.TPMAlgRSA, &tpm20.TPMSRSAParms{})

	failureTests := []struct {
		name        string
		idevidPub   *tpm20.TPMTPublic
		keyTemplate epb.KeyTemplate
		wantErr     error
	}{
		{
			name:        "Nil idevidPub",
			idevidPub:   nil,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInputNil,
		},
		{
			name:        "Unsupported key template",
			idevidPub:   &validIdevidPub,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_UNSPECIFIED,
			wantErr:     ErrUnsupportedKeyTemplate,
		},
		{
			name:        "Attribute mismatch",
			idevidPub:   &pubWithBadAttr,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
		{
			name:        "Wrong Type",
			idevidPub:   &pubWithBadType,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
		{
			name:        "Wrong NameAlg",
			idevidPub:   &pubWithBadNameAlg,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
		{
			name:        "Parameters not ECC",
			idevidPub:   &pubWithMismatchedParams,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
		{
			name:        "Wrong Curve",
			idevidPub:   &pubWithBadCurve,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
		{
			name:        "Wrong Scheme",
			idevidPub:   &pubWithBadScheme,
			keyTemplate: epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384,
			wantErr:     ErrInvalidPubKeyAttributes,
		},
	}

	for _, tc := range failureTests {
		t.Run(tc.name, func(t *testing.T) {
			err := u.VerifyIdevidAttributes(tc.idevidPub, tc.keyTemplate)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("VerifyIDevIDAttributes() returned error %v, want error to be %v", err, tc.wantErr)
			}
		})
	}
}
