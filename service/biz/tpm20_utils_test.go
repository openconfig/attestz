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
