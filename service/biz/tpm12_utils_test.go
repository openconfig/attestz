package biz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math"
	"math/big"

	// #nosec
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	tpm12 "github.com/google/go-tpm/tpm"
)

// TODO: refactor tests to split success and failure cases, and make create bytes helpers more readable.
// This function creates a byte slice representing a TPMSymmetricKeyParms structure.
type symmetricKeyParms struct {
	keyLength *uint32
	blockSize *uint32
	ivSize    *uint32
	iv        *[]byte
}

func (opts symmetricKeyParms) toBytes() []byte {
	buffer := new(bytes.Buffer)

	keyLength := uint32(16)
	if opts.keyLength != nil {
		keyLength = *opts.keyLength
	}
	binaryWriteUint32(buffer, keyLength)

	blockSize := uint32(16)
	if opts.blockSize != nil {
		blockSize = *opts.blockSize
	}
	binaryWriteUint32(buffer, blockSize)

	ivSize := uint32(16)
	if opts.ivSize != nil {
		ivSize = *opts.ivSize
	}
	binaryWriteUint32(buffer, ivSize)

	iv := make([]byte, 16)
	if opts.iv != nil {
		iv = *opts.iv
	}
	buffer.Write(iv)

	return buffer.Bytes()
}

func assertError(t *testing.T, err error, expectedError string, message string) {
	if expectedError == "" {
		if err != nil {
			t.Errorf("%s: got unexpected error: %v", message, err)
		}
	} else {
		if err == nil || !strings.Contains(err.Error(), expectedError) {
			t.Errorf("%s: got error %v, expected error substring: %v", message, err, expectedError)
		}
	}
}

func TestParseSymmetricKeyParms_Success(t *testing.T) {
	iv := make([]byte, 16)
	data := symmetricKeyParms{
		keyLength: ptrUint32(16),
		blockSize: ptrUint32(16),
		ivSize:    ptrUint32(16),
		iv:        &iv,
	}.toBytes()
	u := &DefaultTPM12Utils{}
	result, err := u.ParseSymmetricKeyParms(data)

	if err != nil {
		t.Fatalf("ParseSymmetricKeyParms(%v) returned err: %v, want nil", data, err)
	}

	expected := &TPMSymmetricKeyParms{
		KeyLength: uint32(16),
		BlockSize: uint32(16),
		IV:        make([]byte, 16),
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("ParseSymmetricKeyParms(%v) returned diff (-want +got):\n%s", data, diff)
	}
}

func TestParseSymmetricKeyParms_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		params        symmetricKeyParms
		expectedError string
	}{
		{
			name: "invalid zero IV",
			params: symmetricKeyParms{
				ivSize: ptrUint32(0),
				iv:     &[]byte{},
			},
			expectedError: "failed to read ivSize: read uint32 is zero, expected non-zero",
		},
		{
			name: "Invalid zero keyLength",
			params: symmetricKeyParms{
				keyLength: ptrUint32(0),
			},
			expectedError: "failed to read keyLength",
		},
		{
			name: "Invalid zero blockSize",
			params: symmetricKeyParms{
				blockSize: ptrUint32(0),
			},
			expectedError: "failed to read blockSize",
		},
		{
			name: "Invalid ivSize too small",
			params: symmetricKeyParms{
				ivSize: ptrUint32(8),
			},
			expectedError: "leftover bytes in TPM_SYMMETRIC_KEY_PARMS block",
		},
		{
			name: "Invalid ivSize bigger than iv",
			params: symmetricKeyParms{
				ivSize: ptrUint32(32),
			},
			expectedError: "failed to read IV",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.params.toBytes()
			u := &DefaultTPM12Utils{}
			_, err := u.ParseSymmetricKeyParms(data)
			if err == nil {
				t.Fatalf("ParseSymmetricKeyParms(%v) got nil error, want error containing %q", data, tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseSymmetricKeyParms(%v) got error %v, want error containing %q", data, err, tc.expectedError)
			}
		})
	}
}

// rsaKeyParms provides options for creating TPM_RSA_KEY_PARMS bytes.
type rsaKeyParms struct {
	keyLength    *uint32
	numPrimes    *uint32
	exponent     *[]byte
	exponentSize *uint32
}

// This function creates a byte slice representing TPM_RSA_KEY_PARMS structure
func (opts rsaKeyParms) toBytes() []byte {
	buffer := new(bytes.Buffer)

	keyLength := uint32(2048)
	if opts.keyLength != nil {
		keyLength = *opts.keyLength
	}
	binaryWriteUint32(buffer, keyLength)

	numPrimes := uint32(2)
	if opts.numPrimes != nil {
		numPrimes = *opts.numPrimes
	}
	binaryWriteUint32(buffer, numPrimes)

	exponent := []byte{1, 2, 3}
	if opts.exponent != nil {
		exponent = *opts.exponent
	}
	exponentSize := uint32(len(exponent))
	if opts.exponentSize != nil {
		exponentSize = *opts.exponentSize
	}
	binaryWriteUint32(buffer, exponentSize)
	buffer.Write(exponent)

	return buffer.Bytes()
}

func TestParseRSAKeyParms_Success(t *testing.T) {
	u := &DefaultTPM12Utils{}
	data := rsaKeyParms{
		keyLength: ptrUint32(2048),
		numPrimes: ptrUint32(2),
		exponent:  &[]byte{1, 2, 3},
	}.toBytes()
	result, err := u.ParseRSAKeyParms(data)

	if err != nil {
		t.Fatalf("ParseRSAKeyParms(%v) returned err: %v, want nil", data, err)
	}

	expected := &TPMRSAKeyParms{
		KeyLength: 2048,
		NumPrimes: 2,
		Exponent:  []byte{1, 2, 3},
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("ParseRSAKeyParms(%v) returned diff (-want +got):\n%s", data, diff)
	}
}

func TestParseRSAKeyParms_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		params        rsaKeyParms
		expectedError string
	}{
		{
			name: "Invalid zero keyLength",
			params: rsaKeyParms{
				keyLength: ptrUint32(0),
			},
			expectedError: "failed to read keyLength: read uint32 is zero, expected non-zero",
		},
		{
			name: "Invalid zero numPrimes",
			params: rsaKeyParms{
				numPrimes: ptrUint32(0),
			},
			expectedError: "failed to read numPrimes: read uint32 is zero, expected non-zero",
		},
		{
			name: "Invalid exponentSize too big",
			params: rsaKeyParms{
				exponent:     &[]byte{1, 2, 3, 4},
				exponentSize: ptrUint32(3), // Smaller than actual exponent
			},
			expectedError: "leftover bytes in TPM_RSA_KEY_PARMS block",
		},
		{
			name: "Invalid exponentSize too small",
			params: rsaKeyParms{
				exponentSize: ptrUint32(2),
			},
			expectedError: "leftover bytes in TPM_RSA_KEY_PARMS block",
		},
		{
			name: "Not enough bytes for exponent",
			params: rsaKeyParms{
				exponent:     &[]byte{1, 2, 3},
				exponentSize: ptrUint32(4), // Larger than actual exponent
			},
			expectedError: "failed to read exponent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			data := tc.params.toBytes()
			_, err := u.ParseRSAKeyParms(data)

			if err == nil {
				t.Errorf("ParseRSAKeyParms(%v) got nil error, want error containing %q", data, tc.expectedError)
			} else if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseRSAKeyParms(%v) got error %v, want error containing %q", data, err, tc.expectedError)
			}
		})
	}
}

// keyParms provides options for creating TPM_KEY_PARMS bytes.
type keyParms struct {
	algID     tpm12.Algorithm
	encScheme TPMEncodingScheme
	sigScheme TPMSignatureScheme
	parms     []byte
}

// This function creates a byte slice representing a TPM_KEY_PARMS structure.
func (opts keyParms) toBytes() []byte {
	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, uint32(opts.algID))
	binaryWriteUint16(buffer, uint16(opts.encScheme))
	binaryWriteUint16(buffer, uint16(opts.sigScheme))
	binaryWriteUint32(buffer, uint32(len(opts.parms))) // paramSize
	buffer.Write(opts.parms)
	return buffer.Bytes()
}

func TestParseKeyParmsFromReader_Success(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected *TPMKeyParms
	}{
		{
			name: "Valid RSA KeyParms",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     rsaKeyParms{}.toBytes(), // Use defaults
			}.toBytes(),

			expected: &TPMKeyParms{
				AlgID:     tpm12.AlgRSA,
				EncScheme: EsRSAEsPKCSv15,
				SigScheme: SsRSASaPKCS1v15SHA1,
				Params: TPMParams{
					RSAParams: &TPMRSAKeyParms{
						KeyLength: 2048,
						NumPrimes: 2,
						Exponent:  []byte{1, 2, 3},
					},
				},
			},
		},
		{
			name: "Valid Symmetric KeyParms (AES128)",
			input: keyParms{
				algID:     tpm12.AlgAES128,
				encScheme: EsSymCBCPKCS5,
				sigScheme: SsNone,
				parms:     symmetricKeyParms{}.toBytes(), // Use defaults
			}.toBytes(),

			expected: &TPMKeyParms{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				SigScheme: SsNone,
				Params: TPMParams{
					SymParams: &TPMSymmetricKeyParms{
						KeyLength: 16,
						BlockSize: 16,
						IV:        make([]byte, 16),
					},
				},
			},
		},
		{
			name: "Valid KeyParms with no specific params (SHA1)",
			input: keyParms{
				algID:     tpm12.AlgSHA,
				encScheme: EsNone,
				sigScheme: SsNone,
				parms:     []byte{}, // No params
			}.toBytes(),
			expected: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params:    TPMParams{}, // Should be empty
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			result, err := u.ParseKeyParmsFromReader(reader)

			if err != nil {
				t.Fatalf("ParseKeyParmsFromReader(%v) returned unexpected error: %v", tc.input, err)
			}

			if !cmp.Equal(result, tc.expected) {
				t.Errorf("ParseKeyParmsFromReader(%v) return mismatch:\nGot: %+v\nExpected: %+v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestParseKeyParmsFromReader_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedError string
	}{
		{
			name:          "Invalid AlgID",
			input:         []byte{1, 2, 3, 4},
			expectedError: "invalid algorithmID",
		},
		{
			name:          "Input too short for AlgID",
			input:         []byte{1, 2, 3}, // 3 bytes, needs 4 for AlgID
			expectedError: "failed to read algorithmID",
		},
		{
			name: "Input too short for EncScheme",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     rsaKeyParms{}.toBytes(),
			}.toBytes()[:4], // Truncate after AlgID
			expectedError: "failed to read encScheme",
		},
		{
			name: "Input too short for SigScheme",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     rsaKeyParms{}.toBytes(),
			}.toBytes()[:6], // Truncate after encScheme
			expectedError: "failed to read sigScheme",
		},
		{
			name: "Input too short for ParamSize",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     rsaKeyParms{}.toBytes(),
			}.toBytes()[:8], // Truncate after SigScheme
			expectedError: "failed to read paramSize",
		},
		{
			name: "ParamSize too small for RSA params",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     []byte{1, 2}, // ParamSize will be 2, but RSA params need at least 4 bytes for KeyLength
			}.toBytes(),
			expectedError: "failed to parse RSA key parms",
		},
		{
			name: "Input too short for Parms data",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms:     rsaKeyParms{}.toBytes(),
			}.toBytes()[:14], // Truncate in the middle of parms
			expectedError: "failed to read parms", // Error from readBytes
		},
		{
			name: "Invalid RSA Parms (zero keyLength)",
			input: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms: rsaKeyParms{
					keyLength: ptrUint32(0),
				}.toBytes(),
			}.toBytes(),
			expectedError: "failed to parse RSA key parms: failed to read keyLength: read uint32 is zero, expected non-zero",
		},
		{
			name: "Invalid Symmetric Parms (zero ivSize)",
			input: keyParms{
				algID:     tpm12.AlgAES128,
				encScheme: EsSymCBCPKCS5,
				sigScheme: SsNone,
				parms: symmetricKeyParms{
					ivSize: ptrUint32(0),
					iv:     &[]byte{},
				}.toBytes(),
			}.toBytes(),
			expectedError: "failed to parse Symmetric key parms: failed to read ivSize: read uint32 is zero, expected non-zero",
		},
		{
			name: "Unexpected paramSize for SHA1 (no params expected)",
			input: keyParms{
				algID:     tpm12.AlgSHA,
				encScheme: EsNone,
				sigScheme: SsNone,
				parms:     []byte{1, 2, 3}, // Should be empty, but has data
			}.toBytes(),
			expectedError: "unexpected params size for algorithm SHA1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			_, err := u.ParseKeyParmsFromReader(reader)
			if err == nil {
				t.Fatalf("ParseKeyParmsFromReader(%v) got nil error, want error containing %q", tc.input, tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseKeyParmsFromReader(%v) got error %v, want error containing %q", tc.input, err, tc.expectedError)
			}
		})
	}
}

// identityRequest provides options for creating TPMIdentityReq bytes.
// Fields, if nil or empty, will use default values.
type identityRequest struct {
	asymBlobSize *uint32
	symBlobSize  *uint32
	asymKeyParms []byte
	symKeyParms  []byte
	asymBlob     []byte
	symBlob      []byte
}

// This function creates a byte slice representing a TPM_IDENTITY_REQ structure
// based on the provided options. Default values are used for any unset fields.
func (opts identityRequest) toBytes() []byte {
	// Apply defaults if not provided.
	asymBlobSize := uint32(10)
	if opts.asymBlobSize != nil {
		asymBlobSize = *opts.asymBlobSize
	}
	symBlobSize := uint32(16)
	if opts.symBlobSize != nil {
		symBlobSize = *opts.symBlobSize
	}
	asymKeyParms := keyParms{
		algID:     tpm12.AlgRSA,
		encScheme: EsRSAEsPKCSv15,
		sigScheme: SsRSASaPKCS1v15SHA1,
		parms:     rsaKeyParms{}.toBytes(), // Use defaults
	}.toBytes()
	if opts.asymKeyParms != nil {
		asymKeyParms = opts.asymKeyParms
	}
	symKeyParms := keyParms{
		algID:     tpm12.AlgAES128,
		encScheme: EsSymCBCPKCS5,
		sigScheme: SsNone,
		parms:     symmetricKeyParms{}.toBytes(), // Use defaults
	}.toBytes()
	if opts.symKeyParms != nil {
		symKeyParms = opts.symKeyParms
	}
	asymBlob := make([]byte, asymBlobSize)
	if opts.asymBlob != nil {
		asymBlob = opts.asymBlob
	}
	symBlob := make([]byte, symBlobSize)
	if opts.symBlob != nil {
		symBlob = opts.symBlob
	}

	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, asymBlobSize)
	binaryWriteUint32(buffer, symBlobSize)
	buffer.Write(asymKeyParms)
	buffer.Write(symKeyParms)
	buffer.Write(asymBlob)
	buffer.Write(symBlob)
	return buffer.Bytes()
}

func TestParseIdentityRequestSuccess(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected *TPMIdentityReq
	}{
		{
			name:  "Valid request with RSA and AES, small blobs",
			input: identityRequest{}.toBytes(), // Use all defaults
			expected: &TPMIdentityReq{
				AsymAlgorithm: TPMKeyParms{
					AlgID:     tpm12.AlgRSA,
					EncScheme: EsRSAEsPKCSv15,
					SigScheme: SsRSASaPKCS1v15SHA1,
					Params: TPMParams{
						RSAParams: &TPMRSAKeyParms{
							KeyLength: 2048,
							NumPrimes: 2,
							Exponent:  []byte{1, 2, 3},
						},
					},
				},
				SymAlgorithm: TPMKeyParms{
					AlgID:     tpm12.AlgAES128,
					EncScheme: EsSymCBCPKCS5,
					SigScheme: SsNone,
					Params: TPMParams{
						SymParams: &TPMSymmetricKeyParms{
							KeyLength: 16,
							BlockSize: 16,
							IV:        make([]byte, 16),
						},
					},
				},
				AsymBlob: make([]byte, 10),
				SymBlob:  make([]byte, 16),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			result, err := u.ParseIdentityRequest(tc.input)
			if err != nil {
				t.Errorf("ParseIdentityRequest(%v) got unexpected error: %v", tc.input, err)
			}
			if !cmp.Equal(result, tc.expected) {
				t.Errorf("ParseIdentityRequest(%v) mismatch:\nGot: %+v\nExpected: %+v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestParseIdentityRequestFailure(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name          string
		input         []byte
		expectedError string
	}{
		{
			name: "invalid request with no asymblob",
			input: identityRequest{
				asymBlobSize: ptrUint32(0),
				asymBlob:     []byte{},
			}.toBytes(),
			expectedError: "failed to read asymBlobSize: read uint32 is zero, expected non-zero",
		},
		{
			name: "invalid request with no symblob",
			input: identityRequest{
				symBlobSize: ptrUint32(0),
				symBlob:     []byte{},
			}.toBytes(),
			expectedError: "failed to read symBlobSize: read uint32 is zero, expected non-zero",
		},
		{
			name:          "Input too short for asymBlobSize",
			input:         []byte{1, 2, 3},
			expectedError: "failed to read asymBlobSize",
		},
		{
			name:          "Input too short for symBlobSize",
			input:         []byte{1, 2, 3, 4, 5, 6, 7},
			expectedError: "failed to read symBlobSize",
		},
		{
			name: "Input too short for asymAlgorithm",
			input: identityRequest{
				asymKeyParms: []byte{1, 2, 3}, // Invalid asymKeyParms
			}.toBytes(),
			expectedError: "failed to parse asymAlgorithm (TPM_KEY_PARMS): invalid algorithmID",
		},
		{
			name: "Input too short for symAlgorithm",
			input: identityRequest{
				symKeyParms: []byte{1, 2, 3}, // Invalid symKeyParms
			}.toBytes(),
			expectedError: "failed to parse symAlgorithm (TPM_KEY_PARMS): invalid algorithmID",
		},
		{
			name: "Input too short for asymBlob",
			input: identityRequest{
				asymBlobSize: ptrUint32(10),
				asymBlob:     make([]byte, 5),
			}.toBytes(),
			expectedError: "failed to read symBlob",
		},
		{
			name: "Input too short for symBlob",
			input: identityRequest{
				symBlobSize: ptrUint32(10),
				symBlob:     make([]byte, 5),
			}.toBytes(),
			expectedError: "failed to read symBlob",
		},
		{
			name: "Invalid asymKeyParms (zero keyLength)",
			input: identityRequest{
				asymKeyParms: keyParms{
					algID:     tpm12.AlgRSA,
					encScheme: EsRSAEsPKCSv15,
					sigScheme: SsRSASaPKCS1v15SHA1,
					parms: rsaKeyParms{
						keyLength: ptrUint32(0),
					}.toBytes(),
				}.toBytes(),
			}.toBytes(),
			expectedError: "failed to parse asymAlgorithm (TPM_KEY_PARMS): failed to parse RSA key parms",
		},
		{
			name: "Invalid symKeyParms (zero ivSize)",
			input: identityRequest{
				symKeyParms: keyParms{
					algID:     tpm12.AlgAES128,
					encScheme: EsSymCBCPKCS5,
					sigScheme: SsNone,
					parms: symmetricKeyParms{
						ivSize: ptrUint32(0),
						iv:     &[]byte{},
					}.toBytes(),
				}.toBytes(),
			}.toBytes(),
			expectedError: "failed to parse symAlgorithm (TPM_KEY_PARMS): failed to parse Symmetric key parms",
		},
		{
			name:          "leftover bytes",
			input:         append(identityRequest{}.toBytes(), 1, 2, 3),
			expectedError: "leftover bytes in TPM_IDENTITY_REQ after parsing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			_, err := u.ParseIdentityRequest(tc.input)
			if err == nil {
				t.Fatalf("ParseIdentityRequest(%v) got nil error, want error containing %q", tc.input, tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseIdentityRequest(%v) got error %v, want error containing %q", tc.input, err, tc.expectedError)
			}
		})
	}
}

func TestDecryptWithPrivateKey(t *testing.T) {
	// Generate a sample RSA key pair for testing.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	sampleData := []byte("test data to encrypt and decrypt")

	testCases := []struct {
		name          string
		algo          tpm12.Algorithm
		encScheme     TPMEncodingScheme
		expectedError string
	}{
		{
			name:          "RSA PKCS1v15 success",
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsPKCSv15,
			expectedError: "",
		},
		{
			name:          "RSA OAEP success",
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsOAEPSHA1MGF1,
			expectedError: "",
		},
		{
			name:          "Unsupported algorithm",
			algo:          tpm12.AlgAES128,
			encScheme:     EsRSAEsPKCSv15,
			expectedError: "unsupported algorithm",
		},
		{
			name:          "Unsupported encoding scheme",
			algo:          tpm12.AlgRSA,
			encScheme:     EsSymCBCPKCS5,
			expectedError: "unsupported encoding scheme",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var encryptedData []byte
			var err error
			if tc.expectedError == "" {
				// Encrypt the data using the public key.
				switch tc.encScheme {
				case EsRSAEsPKCSv15:
					encryptedData, err = rsa.EncryptPKCS1v15(rand.Reader, publicKey, sampleData)
				case EsRSAEsOAEPSHA1MGF1:
					// #nosec
					encryptedData, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, sampleData, nil)
				}
				if err != nil {
					t.Fatalf("Failed to encrypt data: %v", err)
				}
			} else {
				encryptedData = sampleData
			}

			u := &DefaultTPM12Utils{}
			decryptedData, err := u.DecryptWithPrivateKey(context.Background(), privateKey, encryptedData, tc.algo, tc.encScheme)

			assertError(t, err, tc.expectedError, "DecryptWithPrivateKey")

			if tc.expectedError == "" {
				if !cmp.Equal(decryptedData, sampleData) {
					t.Errorf("Decrypted data mismatch: got %v, expected %v", decryptedData, sampleData)
				}
			}
		})
	}
}

// symmetricKey provides options for creating TPMSymmetricKey bytes.
type symmetricKey struct {
	algID     *tpm12.Algorithm
	encScheme *TPMEncodingScheme
	key       []byte
}

// This function creates a byte slice representing a TPMSymmetricKey structure.
func (opts symmetricKey) toBytes() []byte {
	buffer := new(bytes.Buffer)

	algID := tpm12.AlgAES128
	if opts.algID != nil {
		algID = *opts.algID
	}
	binaryWriteUint32(buffer, uint32(algID))

	encScheme := EsSymCBCPKCS5
	if opts.encScheme != nil {
		encScheme = *opts.encScheme
	}
	binaryWriteUint16(buffer, uint16(encScheme))

	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if opts.key != nil {
		key = opts.key
	}
	binaryWriteUint16(buffer, uint16(len(key)))
	buffer.Write(key)
	return buffer.Bytes()
}

func TestParseSymmetricKey(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expected      *TPMSymmetricKey
		expectedError string
	}{
		{
			name: "Valid key",
			input: symmetricKey{
				key: []byte{1, 2, 3, 4}}.toBytes(),
			expected: &TPMSymmetricKey{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				Key:       []byte{1, 2, 3, 4},
			},
			expectedError: "",
		},
		{
			name: "Invalid empty key",
			input: symmetricKey{
				key: []byte{}}.toBytes(),
			expectedError: "key cannot be empty",
		},
		{
			name:          "Input too short for AlgID",
			input:         []byte{1, 2, 3},
			expectedError: "failed to read algorithmID",
		},
		{
			name: "Input too short for EncScheme",
			input: symmetricKey{
				key: []byte{1, 2, 3, 4}}.toBytes()[:4],
			expectedError: "failed to read encScheme",
		},
		{
			name: "Input too short for keySize",
			input: symmetricKey{
				key: []byte{1, 2, 3, 4}}.toBytes()[:6],
			expectedError: "failed to read keySize",
		},
		{
			name: "Input too short for key data",
			input: symmetricKey{
				key: []byte{1, 2, 3, 4}}.toBytes()[:10], // 4+2+2+2 bytes
			expectedError: "failed to read key (size 4)",
		},
		{
			name: "Leftover bytes",
			input: append(symmetricKey{
				key: []byte{1, 2, 3, 4}}.toBytes(), 0xDE, 0xAD, 0xBE, 0xEF),
			expectedError: "leftover bytes in TPMSymmetricKey block",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			result, err := u.ParseSymmetricKey(tc.input)
			assertError(t, err, tc.expectedError, "ParseSymmetricKey")
			if tc.expectedError == "" {
				if !cmp.Equal(result, tc.expected) {
					t.Errorf("ParseSymmetricKey mismatch:\nGot: %+v\nExpected: %+v", result, tc.expected)
				}
			}
		})
	}
}

func TestSerializeStorePubKey(t *testing.T) {
	testCases := []struct {
		name          string
		pubKey        *TPMStorePubKey
		expectedBytes []byte
		expectedError string
	}{
		{
			name: "Valid PubKey",
			pubKey: &TPMStorePubKey{
				KeyLength: 8,
				Key:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x00, 0x08, // KeyLength (8)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Key
			},
			expectedError: "",
		},
		{
			name: "Empty Key",
			pubKey: &TPMStorePubKey{
				KeyLength: 0,
				Key:       []byte{},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x00, 0x00, // KeyLength (0)
			},
			expectedError: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			gotBytes, err := u.SerializeStorePubKey(tc.pubKey)

			assertError(t, err, tc.expectedError, "SerializeStorePubKey")

			if tc.expectedError == "" {
				if diff := cmp.Diff(tc.expectedBytes, gotBytes); diff != "" {
					t.Errorf("SerializeStorePubKey mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestSerializeRSAKeyParms(t *testing.T) {
	testCases := []struct {
		name          string
		rsaParms      *TPMRSAKeyParms
		expectedBytes []byte
	}{
		{
			name: "Valid RSA Params",
			rsaParms: &TPMRSAKeyParms{
				KeyLength: 2048,
				NumPrimes: 2,
				Exponent:  []byte{0x01, 0x00, 0x01}, // 65537
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x08, 0x00, // KeyLength (2048)
				0x00, 0x00, 0x00, 0x02, // NumPrimes (2)
				0x00, 0x00, 0x00, 0x03, // Exponent Size (3)
				0x01, 0x00, 0x01, // Exponent
			},
		},
		{
			name: "Empty Exponent",
			rsaParms: &TPMRSAKeyParms{
				KeyLength: 1024,
				NumPrimes: 2,
				Exponent:  []byte{},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x04, 0x00, // KeyLength (1024)
				0x00, 0x00, 0x00, 0x02, // NumPrimes (2)
				0x00, 0x00, 0x00, 0x00, // Exponent Size (0)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			gotBytes, err := u.SerializeRSAKeyParms(tc.rsaParms)
			if err != nil {
				t.Errorf("SerializeRSAKeyParms(%+v) returned unexpected error: %v", tc.rsaParms, err)
			}

			if diff := cmp.Diff(tc.expectedBytes, gotBytes); diff != "" {
				t.Errorf("SerializeRSAKeyParms(%+v) mismatch (-want +got):\n%s", tc.rsaParms, diff)
			}
		})
	}
}

func TestSerializeSymmetricKeyParms(t *testing.T) {
	testCases := []struct {
		name          string
		symParms      *TPMSymmetricKeyParms
		expectedBytes []byte
	}{
		{
			name: "Valid Symmetric Params",
			symParms: &TPMSymmetricKeyParms{
				KeyLength: 16,
				BlockSize: 16,
				IV:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x00, 0x10, // KeyLength (16)
				0x00, 0x00, 0x00, 0x10, // BlockSize (16)
				0x00, 0x00, 0x00, 0x10, // IV Size (16)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // IV
			},
		},
		{
			name: "Empty IV",
			symParms: &TPMSymmetricKeyParms{
				KeyLength: 16,
				BlockSize: 16,
				IV:        []byte{},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x00, 0x10, // KeyLength (16)
				0x00, 0x00, 0x00, 0x10, // BlockSize (16)
				0x00, 0x00, 0x00, 0x00, // IV Size (0)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			gotBytes, err := u.SerializeSymmetricKeyParms(tc.symParms)
			if err != nil {
				t.Errorf("SerializeSymmetricKeyParms(%+v) returned unexpected error: %v", tc.symParms, err)
			}

			if diff := cmp.Diff(tc.expectedBytes, gotBytes); diff != "" {
				t.Errorf("SerializeSymmetricKeyParms(%+v) mismatch (-want +got):\n%s", tc.symParms, diff)
			}
		})
	}
}

func TestSerializeKeyParms_Success(t *testing.T) {
	u := &DefaultTPM12Utils{}

	testCases := []struct {
		name          string
		keyParms      *TPMKeyParms
		expectedBytes []byte
	}{
		{
			name: "RSA KeyParms",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgRSA,
				EncScheme: EsRSAEsPKCSv15,
				SigScheme: SsRSASaPKCS1v15SHA1,
				Params: TPMParams{
					RSAParams: &TPMRSAKeyParms{KeyLength: 2048, NumPrimes: 2, Exponent: []byte{0x01, 0x00, 0x01}},
				},
			},
			expectedBytes: keyParms{
				algID:     tpm12.AlgRSA,
				encScheme: EsRSAEsPKCSv15,
				sigScheme: SsRSASaPKCS1v15SHA1,
				parms: rsaKeyParms{
					exponent: &[]byte{0x01, 0x00, 0x01},
				}.toBytes(),
			}.toBytes(),
		},
		{
			name: "Symmetric KeyParms",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				SigScheme: SsNone,
				Params: TPMParams{
					SymParams: &TPMSymmetricKeyParms{KeyLength: 16, BlockSize: 16, IV: make([]byte, 16)},
				},
			},
			expectedBytes: keyParms{
				algID:     tpm12.AlgAES128,
				encScheme: EsSymCBCPKCS5,
				sigScheme: SsNone,
				parms:     symmetricKeyParms{}.toBytes(),
			}.toBytes(),
		},
		{
			name: "KeyParms with No Params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params:    TPMParams{},
			},
			expectedBytes: keyParms{
				algID:     tpm12.AlgSHA,
				encScheme: EsNone,
				sigScheme: SsNone,
				parms:     []byte{},
			}.toBytes(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes, err := u.SerializeKeyParms(tc.keyParms)
			if err != nil {
				t.Errorf("SerializeKeyParms(%+v) returned unexpected error: %v", tc.keyParms, err)
			}

			if diff := cmp.Diff(tc.expectedBytes, gotBytes); diff != "" {
				t.Errorf("SerializeKeyParms(%+v) mismatch (-want +got):\n%s", tc.keyParms, diff)
			}
		})
	}
}

func TestSerializeKeyParms_Failure(t *testing.T) {
	u := &DefaultTPM12Utils{}

	testCases := []struct {
		name          string
		keyParms      *TPMKeyParms
		expectedError error
	}{
		{
			name: "RSA algorithm with Symmetric key params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgRSA,
				EncScheme: EsRSAEsPKCSv15,
				SigScheme: SsRSASaPKCS1v15SHA1,
				Params: TPMParams{
					SymParams: &TPMSymmetricKeyParms{},
				},
			},
			expectedError: ErrUnexpectedParams,
		},
		{
			name: "Symmetric algorithm with RSA key params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				SigScheme: SsNone,
				Params: TPMParams{
					RSAParams: &TPMRSAKeyParms{},
				},
			},
			expectedError: ErrUnexpectedParams,
		},
		{
			name: "SHA algorithm with RSA key params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params: TPMParams{
					RSAParams: &TPMRSAKeyParms{},
				},
			},
			expectedError: ErrUnexpectedParams,
		},
		{
			name: "SHA algorithm with Symmetric key params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params: TPMParams{
					SymParams: &TPMSymmetricKeyParms{},
				},
			},
			expectedError: ErrUnexpectedParams,
		},
		{
			name:          "Nil KeyParms",
			keyParms:      nil,
			expectedError: ErrNilInput,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.SerializeKeyParms(tc.keyParms)
			if !errors.Is(err, tc.expectedError) {
				t.Errorf("SerializeKeyParms(%+v) got error %v, want error %v", tc.keyParms, err, tc.expectedError)
			}
		})
	}
}

func TestSerializePubKey(t *testing.T) {
	// Example TPMPubKey for testing
	tpmPubKey := &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     tpm12.AlgRSA,
			EncScheme: EsRSAEsOAEPSHA1MGF1,
			SigScheme: SsRSASaPKCS1v15SHA1,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					KeyLength: 2048,
					NumPrimes: 2,
					Exponent:  []byte{0x01, 0x00, 0x01},
				},
			},
		},
		PubKey: TPMStorePubKey{
			KeyLength: 256, // 2048 bits / 8
			Key:       bytes.Repeat([]byte{0xAA}, 256),
		},
	}

	u := &DefaultTPM12Utils{}
	keyParms, err := u.SerializeKeyParms(&tpmPubKey.AlgorithmParms)
	if err != nil {
		t.Fatalf("SerializeKeyParms returned unexpected error: %v", err)
	}
	pubKey, err := u.SerializeStorePubKey(&tpmPubKey.PubKey)
	if err != nil {
		t.Fatalf("SerializeStorePubKey returned unexpected error: %v", err)
	}

	expectedBytes := append(keyParms, pubKey...)

	gotBytes, err := u.SerializePubKey(tpmPubKey)
	if err != nil {
		t.Errorf("SerializePubKey(%+v) returned unexpected error: %v", tpmPubKey, err)
	}

	if diff := cmp.Diff(expectedBytes, gotBytes); diff != "" {
		t.Errorf("SerializePubKey(%+v) mismatch (-want +got):\n%s", tpmPubKey, diff)
	}
}

func TestSerializeIdentityContents(t *testing.T) {
	// Create a sample IdentityPubKey
	samplePubKey := &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     tpm12.AlgRSA,
			EncScheme: EsRSAEsOAEPSHA1MGF1,
			SigScheme: SsRSASaPKCS1v15SHA1,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					KeyLength: 2048,
					NumPrimes: 2,
					Exponent:  []byte{0x01, 0x00, 0x01},
				},
			},
		},
		PubKey: TPMStorePubKey{
			KeyLength: 256,
			Key:       bytes.Repeat([]byte{0xAB}, 256),
		},
	}
	u := &DefaultTPM12Utils{}
	identityPubKeyBytes, err := u.SerializePubKey(samplePubKey)
	if err != nil {
		t.Fatalf("Failed to serialize sample TPMPubKey: %v", err)
	}

	// Create a sample LabelPrivCADigest
	sampleDigest := bytes.Repeat([]byte{0xCD}, 20) // SHA1 is 20 bytes

	identityContents := &TPMIdentityContents{
		TPMStructVer:      GetDefaultTPMStructVer(),
		Ordinal:           0x00000079,
		LabelPrivCADigest: sampleDigest,
		IdentityPubKey:    *samplePubKey,
	}

	// Manually construct the expected byte slice
	var expectedBuf bytes.Buffer
	expectedBuf.Write([]byte{0x01, 0x01, 0x00, 0x00}) // serialized default struct version
	binaryWriteUint32(&expectedBuf, identityContents.Ordinal)
	expectedBuf.Write(identityContents.LabelPrivCADigest)
	expectedBuf.Write(identityPubKeyBytes)
	expectedBytes := expectedBuf.Bytes()

	gotBytes, err := u.SerializeIdentityContents(identityContents)
	if err != nil {
		t.Errorf("SerializeIdentityContents(%+v) returned unexpected error: %v", identityContents, err)
	}

	if diff := cmp.Diff(expectedBytes, gotBytes); diff != "" {
		t.Errorf("SerializeIdentityContents(%+v) mismatch (-want +got):\n%s", identityContents, diff)
	}
}

func TestConstructPubKey(t *testing.T) {
	u := &DefaultTPM12Utils{}
	// Success Cases
	t.Run("Success", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		publicKey := &privateKey.PublicKey

		exponent := uint32(publicKey.E)
		if exponent == 0 {
			exponent = 65537
		}

		want := &TPMPubKey{
			AlgorithmParms: TPMKeyParms{
				AlgID:     tpm12.AlgRSA,
				EncScheme: EsRSAEsOAEPSHA1MGF1,
				SigScheme: SsRSASaPKCS1v15SHA1,
				Params: TPMParams{
					RSAParams: &TPMRSAKeyParms{
						KeyLength: uint32(publicKey.N.BitLen()),
						NumPrimes: 2,
						Exponent:  binary.BigEndian.AppendUint32([]byte{}, exponent),
					},
				},
			},
			PubKey: TPMStorePubKey{
				KeyLength: uint32(len(publicKey.N.Bytes())),
				Key:       publicKey.N.Bytes(),
			},
		}

		got, err := u.ConstructPubKey(publicKey)
		if err != nil {
			t.Errorf("ConstructTPMPubKey(%+v) returned unexpected error: %v", publicKey, err)
		}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ConstructTPMPubKey(%+v) returned unexpected diff (-want +got):\n%s", publicKey, diff)
		}
	})

	// Failure Cases
	testCases := []struct {
		name          string
		publicKey     *rsa.PublicKey
		expectedError string
	}{
		{
			name:          "Nil PublicKey",
			publicKey:     nil,
			expectedError: "publicKey or its modulus cannot be nil",
		},
		{
			name:          "Nil PublicKey.N",
			publicKey:     &rsa.PublicKey{},
			expectedError: "publicKey or its modulus cannot be nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.ConstructPubKey(tc.publicKey)
			assertError(t, err, tc.expectedError, "ConstructTPMPubKey")
		})
	}
}

func TestConstructIdentityContents(t *testing.T) {
	u := &DefaultTPM12Utils{}
	// Success Case
	t.Run("Success", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}
		publicKey := &privateKey.PublicKey

		// Construct the expected IdentityPubKey
		expectedTPMPubKey, err := u.ConstructPubKey(publicKey)
		if err != nil {
			t.Fatalf("Failed to construct expected TPMPubKey: %v", err)
		}

		// Manually construct the expected LabelPrivCADigest
		privacyCABytes, err := u.SerializePubKey(expectedTPMPubKey)
		if err != nil {
			t.Fatalf("Failed to serialize TPMPubKey for test: %v", err)
		}
		identityLabel := []byte("Identity")
		hashInput := append(identityLabel, privacyCABytes...)
		hasher := sha1.New()
		hasher.Write(hashInput)
		expectedDigest := hasher.Sum(nil)

		want := &TPMIdentityContents{
			TPMStructVer:      GetDefaultTPMStructVer(),
			Ordinal:           0x00000079,
			LabelPrivCADigest: expectedDigest,
			IdentityPubKey:    *expectedTPMPubKey,
		}

		got, err := u.ConstructIdentityContents(publicKey)
		if err != nil {
			t.Errorf("ConstructIdentityContents(%+v) returned unexpected error: %v", publicKey, err)
		}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("ConstructIdentityContents(%+v) returned unexpected diff (-want +got):\n%s", publicKey, diff)
		}
	})

	// Failure Case
	t.Run("Failure - Nil PublicKey", func(t *testing.T) {
		_, err := u.ConstructIdentityContents(nil)
		expectedError := "failed to construct TPMPubKey: publicKey or its modulus cannot be nil"
		assertError(t, err, expectedError, "ConstructIdentityContents")
	})
}

func defaultTestAik() TPMPubKey {
	return TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     tpm12.AlgRSA,
			EncScheme: EsRSAEsPKCSv15,
			SigScheme: SsRSASaPKCS1v15SHA1,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					KeyLength: 2048,
					NumPrimes: 2,
					Exponent:  []byte{1, 0, 1},
				},
			},
		},
		PubKey: TPMStorePubKey{
			KeyLength: 256,
			Key:       make([]byte, 256),
		},
	}
}

// storePubkey provides options for creating TPM_STORE_PUBKEY bytes.
type storePubkey struct {
	key       []byte
	keyLength *uint32
}

// This function creates a byte slice representing a TPM_STORE_PUBKEY structure.
func (opts storePubkey) toBytes() []byte {
	buffer := new(bytes.Buffer)
	key := opts.key
	if key == nil {
		key = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} // Default key
	}

	var keyLength uint32
	if opts.keyLength != nil {
		keyLength = *opts.keyLength
	} else {
		keyLength = uint32(len(key))
	}
	// Write the keyLength to the buffer.
	binaryWriteUint32(buffer, keyLength)
	buffer.Write(key)
	return buffer.Bytes()
}

// pubKey provides options for creating TPM_PUBKEY bytes.
type pubKey struct {
	algID     *tpm12.Algorithm
	encScheme *TPMEncodingScheme
	sigScheme *TPMSignatureScheme
	parms     []byte
	pubKey    []byte
	pubKeyLen *uint32
}

// This function  creates a byte slice representing a TPM_PUBKEY structure.
func (opts pubKey) toBytes() []byte {
	buffer := new(bytes.Buffer)
	aik := defaultTestAik()

	algID := aik.AlgorithmParms.AlgID
	if opts.algID != nil {
		algID = *opts.algID
	}
	encScheme := aik.AlgorithmParms.EncScheme
	if opts.encScheme != nil {
		encScheme = *opts.encScheme
	}
	sigScheme := aik.AlgorithmParms.SigScheme
	if opts.sigScheme != nil {
		sigScheme = *opts.sigScheme
	}
	parms := rsaKeyParms{
		keyLength: &aik.AlgorithmParms.Params.RSAParams.KeyLength,
		numPrimes: &aik.AlgorithmParms.Params.RSAParams.NumPrimes,
		exponent:  &aik.AlgorithmParms.Params.RSAParams.Exponent,
	}.toBytes()
	if opts.parms != nil {
		parms = opts.parms
	}

	buffer.Write(keyParms{
		algID:     algID,
		encScheme: encScheme,
		sigScheme: sigScheme,
		parms:     parms,
	}.toBytes())
	if opts.pubKey != nil || opts.pubKeyLen != nil {
		buffer.Write(storePubkey{
			key:       opts.pubKey,
			keyLength: opts.pubKeyLen}.toBytes())
	} else {
		buffer.Write(storePubkey{
			key:       aik.PubKey.Key,
			keyLength: &aik.PubKey.KeyLength}.toBytes())
	}
	return buffer.Bytes()
}

func TestParseStorePubKeyFromReader_Success(t *testing.T) {
	testCases := []struct {
		name     string
		options  storePubkey
		expected *TPMStorePubKey
	}{
		{
			name:    "Valid TPMStorePubKey",
			options: storePubkey{},
			expected: &TPMStorePubKey{
				KeyLength: 10,
				Key:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.options.toBytes())
			u := &DefaultTPM12Utils{}
			result, err := u.ParseStorePubKeyFromReader(reader)

			if err != nil {
				t.Fatalf("ParseStorePubKeyFromReader(%v) returned err: %v, want nil ", tc.options, err)
			}

			if !cmp.Equal(result, tc.expected) {
				t.Errorf("ParseStorePubKeyFromReader mismatch:\nGot: %+v\nExpected: %+v", result, tc.expected)
			}
			if reader.Len() != 0 {
				t.Errorf("ParseStorePubKeyFromReader left unread bytes: %d", reader.Len())
			}
		})
	}
}

func TestParseStorePubKeyFromReader_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedError string
	}{
		{
			name:          "Input too short for KeyLength",
			input:         []byte{1, 2, 3},
			expectedError: "failed to read keyLength",
		},
		{
			name:          "Input too short for Key",
			input:         storePubkey{keyLength: ptrUint32(15)}.toBytes(),
			expectedError: "failed to read key",
		},
		{
			name:          "Zero KeyLength",
			input:         storePubkey{keyLength: ptrUint32(0)}.toBytes(),
			expectedError: "keyLength cannot be zero",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			_, err := u.ParseStorePubKeyFromReader(reader)
			if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseStorePubKeyFromReader(%v) got error %v, want error containing %q", tc.input, err, tc.expectedError)
			}
		})
	}
}

func TestParsePubKeyFromReader_Success(t *testing.T) {
	defaultOpts := pubKey{}

	testCases := []struct {
		name     string
		input    []byte
		expected *TPMPubKey
	}{
		{
			name:  "Valid TPMPubKey",
			input: defaultOpts.toBytes(),
			expected: &TPMPubKey{
				AlgorithmParms: TPMKeyParms{
					AlgID:     tpm12.AlgRSA,
					EncScheme: EsRSAEsPKCSv15,
					SigScheme: SsRSASaPKCS1v15SHA1,
					Params: TPMParams{
						RSAParams: &TPMRSAKeyParms{
							KeyLength: 2048,
							NumPrimes: 2,
							Exponent:  []byte{1, 0, 1},
						},
					},
				},
				PubKey: TPMStorePubKey{
					KeyLength: 256,
					Key:       make([]byte, 256),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			result, err := u.ParsePubKeyFromReader(reader)

			if err != nil {
				t.Fatalf("ParsePubKeyFromReader(%v) returned err: %v, want nil", tc.input, err)
			}

			if !cmp.Equal(result, tc.expected) {
				t.Errorf("ParsePubKeyFromReader mismatch:\nGot: %+v\nExpected: %+v", result, tc.expected)
			}
			if reader.Len() != 0 {
				t.Errorf("ParsePubKeyFromReader left unread bytes: %d", reader.Len())
			}
		})
	}
}

func TestParsePubKeyFromReader_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedError string
	}{
		{
			name: "Invalid AlgorithmParms",
			input: pubKey{
				parms: []byte{1}, // Invalid parms
			}.toBytes(),
			expectedError: "failed to parse AlgorithmParms",
		},
		{
			name: "Input too short for AlgorithmParms",
			input: pubKey{
				parms: []byte{1, 2, 3, 4, 5},
			}.toBytes(),
			expectedError: "failed to parse AlgorithmParms",
		},
		{
			name: "Input too short for PubKey",
			input: pubKey{
				pubKey:    []byte{1, 2, 3, 4, 5},
				pubKeyLen: ptrUint32(10),
			}.toBytes(),
			expectedError: "failed to parse PubKey",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			_, err := u.ParsePubKeyFromReader(reader)
			if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParsePubKeyFromReader(%v) got error %v, want error containing %q", tc.input, err, tc.expectedError)
			}
		})
	}
}

// identityProof provides options for creating TPMIdentityProof bytes for testing.
// Fields left nil will use default values within the build function.
type identityProof struct {
	TPMStructVer          *TPMStructVer
	AIK                   *TPMPubKey
	LabelArea             []byte
	IdentityBinding       []byte
	EndorsementCredential []byte
	PlatformCredential    []byte
	ConformanceCredential []byte

	// Size overrides
	LabelAreaSize             *uint32
	IdentityBindingSize       *uint32
	EndorsementCredentialSize *uint32
	PlatformCredentialSize    *uint32
	ConformanceCredentialSize *uint32
}

func buildIdentityProofBytes(t *testing.T, opts identityProof) []byte {
	t.Helper()
	buf := new(bytes.Buffer)

	ver := GetDefaultTPMStructVer()
	if opts.TPMStructVer != nil {
		ver = *opts.TPMStructVer
	}
	err := binary.Write(buf, binary.BigEndian, ver)
	if err != nil {
		t.Fatalf("Failed to write TPMStructVer: %v", err)
	}

	label := []byte("label")
	if opts.LabelArea != nil {
		label = opts.LabelArea
	}
	binding := []byte("binding")
	if opts.IdentityBinding != nil {
		binding = opts.IdentityBinding
	}
	endorse := []byte("endorse")
	if opts.EndorsementCredential != nil {
		endorse = opts.EndorsementCredential
	}
	platform := []byte("platform")
	if opts.PlatformCredential != nil {
		platform = opts.PlatformCredential
	}
	conform := []byte("conform")
	if opts.ConformanceCredential != nil {
		conform = opts.ConformanceCredential
	}

	// Write sizes first
	labelSize := uint32(len(label))
	if opts.LabelAreaSize != nil {
		labelSize = *opts.LabelAreaSize
	}
	binaryWriteUint32(buf, labelSize)

	bindingSize := uint32(len(binding))
	if opts.IdentityBindingSize != nil {
		bindingSize = *opts.IdentityBindingSize
	}
	binaryWriteUint32(buf, bindingSize)

	endorseSize := uint32(len(endorse))
	if opts.EndorsementCredentialSize != nil {
		endorseSize = *opts.EndorsementCredentialSize
	}
	binaryWriteUint32(buf, endorseSize)

	platformSize := uint32(len(platform))
	if opts.PlatformCredentialSize != nil {
		platformSize = *opts.PlatformCredentialSize
	}
	binaryWriteUint32(buf, platformSize)

	conformSize := uint32(len(conform))
	if opts.ConformanceCredentialSize != nil {
		conformSize = *opts.ConformanceCredentialSize
	}
	binaryWriteUint32(buf, conformSize)

	// Then write the AIK
	aik := defaultTestAik()
	if opts.AIK != nil {
		aik = *opts.AIK
	}
	u := &DefaultTPM12Utils{}
	aikBytes, err := u.SerializePubKey(&aik)
	if err != nil {
		t.Fatalf("Failed to serialize AIK: %v", err)
	}
	buf.Write(aikBytes)

	// Then write the data
	buf.Write(label)
	buf.Write(binding)
	buf.Write(endorse)
	buf.Write(platform)
	buf.Write(conform)

	return buf.Bytes()
}

func TestParseIdentityProof_Success(t *testing.T) {
	defaultAIK := defaultTestAik()
	testCases := []struct {
		name     string
		options  identityProof
		expected *TPMIdentityProof
	}{
		{
			name:    "Valid Identity Proof",
			options: identityProof{}, // Use all defaults
			expected: &TPMIdentityProof{
				TPMStructVer:           GetDefaultTPMStructVer(),
				AttestationIdentityKey: defaultAIK,
				LabelArea:              []byte("label"),
				IdentityBinding:        []byte("binding"),
				EndorsementCredential:  []byte("endorse"),
				PlatformCredential:     []byte("platform"),
				ConformanceCredential:  []byte("conform"),
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := buildIdentityProofBytes(t, tc.options)
			u := &DefaultTPM12Utils{}
			result, err := u.ParseIdentityProof(input)
			if err != nil {
				t.Fatalf("ParseIdentityProof(%v) returned err: %v, want nil", tc.options, err)
			}

			if !cmp.Equal(result, tc.expected, cmp.AllowUnexported(TPMKeyParms{})) {
				t.Errorf("ParseIdentityProof mismatch:\nGot: %+v\nExpected: %+v\nDiff: %s", result, tc.expected, cmp.Diff(result, tc.expected, cmp.AllowUnexported(TPMKeyParms{})))
			}
		})
	}
}

func TestParseIdentityProof_Failure(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expectedError string
	}{
		{
			// Input is shorter than the minimum size of the TPMStructVer.
			name:          "Input too short for TPMStructVer",
			input:         buildIdentityProofBytes(t, identityProof{})[:3],
			expectedError: "failed to read TPMStructVer",
		},
		{
			// Input is long enough for TPMStructVer, but too short for the LabelArea size field.
			name:          "Input too short for LabelArea size",
			input:         buildIdentityProofBytes(t, identityProof{})[:4],
			expectedError: "failed to read LabelArea size",
		},
		{
			// Input is long enough for LabelArea size, but too short for the IdentityBinding size field.
			name:          "Input too short for IdentityBinding size",
			input:         buildIdentityProofBytes(t, identityProof{})[:8],
			expectedError: "failed to read IdentityBinding size",
		},
		{
			// Input is truncated within the AttestationIdentityKey field.
			name:          "Input too short for AIK",
			input:         buildIdentityProofBytes(t, identityProof{})[:24],
			expectedError: "failed to parse AttestationIdentityKey",
		},
		{
			name: "LabelAreaSize too large",
			input: buildIdentityProofBytes(t, identityProof{
				LabelAreaSize: ptrUint32(100), // Larger than available bytes
			}),
			expectedError: "failed to read LabelArea",
		},
		{
			name: "IdentityBindingSize too large",
			input: buildIdentityProofBytes(t, identityProof{
				IdentityBindingSize: ptrUint32(100),
			}),
			expectedError: "failed to read IdentityBinding",
		},
		{
			name: "EndorsementCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProof{
				EndorsementCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read EndorsementCredential",
		},
		{
			name: "PlatformCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProof{
				PlatformCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read PlatformCredential",
		},
		{
			name: "ConformanceCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProof{
				ConformanceCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read ConformanceCredential",
		},
		{
			// Input has extra bytes appended after a valid TPMIdentityProof structure.
			name:          "Leftover bytes",
			input:         append(buildIdentityProofBytes(t, identityProof{}), 0xDE, 0xAD),
			expectedError: "leftover bytes in TPM_IDENTITY_PROOF block",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			_, err := u.ParseIdentityProof(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("ParseIdentityProof(%v) got error %v, want error containing %q", tc.input, err, tc.expectedError)
			}
		})
	}
}

func TestNewAESCBCKeySuccess(t *testing.T) {
	tests := []struct {
		name        string
		algo        tpm12.Algorithm
		expectedLen int
	}{
		{
			name:        "AES128",
			algo:        tpm12.AlgAES128,
			expectedLen: 16,
		},
		{
			name:        "AES192",
			algo:        tpm12.AlgAES192,
			expectedLen: 24,
		},
		{
			name:        "AES256",
			algo:        tpm12.AlgAES256,
			expectedLen: 32,
		},
	}

	u := &DefaultTPM12Utils{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			symKey, err := u.NewAESCBCKey(test.algo)
			if err != nil {
				t.Fatalf("NewAESCBCKey(%v) failed: %v", test.algo, err)
			}
			if symKey.AlgID != test.algo {
				t.Errorf("NewAESCBCKey returned AlgID %v(%v), want %v(%v)", symKey.AlgID.String(), symKey.AlgID, test.algo.String(), test.algo)
			}
			if symKey.EncScheme != EsSymCBCPKCS5 {
				t.Errorf("NewAESCBCKey(%v) returned EncScheme %v, want %v", test.algo.String(), symKey.EncScheme, EsSymCBCPKCS5)
			}
			if len(symKey.Key) != test.expectedLen {
				t.Errorf("NewAESCBCKey(%v) returned key of length %d, want %d", test.algo.String(), len(symKey.Key), test.expectedLen)
			}
		})
	}
}

func TestNewAESCBCKeyFailure(t *testing.T) {
	tests := []struct {
		name string
		algo tpm12.Algorithm
	}{
		{
			name: "UnsupportedRSA",
			algo: tpm12.AlgRSA,
		},
		{
			name: "UnsupportedSHA1",
			algo: tpm12.AlgSHA,
		},
		{
			name: "UnsupportedHMAC",
			algo: tpm12.AlgHMAC,
		},
	}

	u := &DefaultTPM12Utils{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			symKey, err := u.NewAESCBCKey(test.algo)
			if err == nil {
				t.Errorf("NewAESCBCKey(%v) succeeded, want error", test.algo)
			}
			if symKey != nil {
				t.Errorf("NewAESCBCKey(%v) returned non-nil symmetric key: %v, want nil", test.algo, symKey)
			}
		})
	}
}

// TODO: Add vector based test to test encryption and padding for EncryptWithAES
func TestEncryptWithAESSuccess(t *testing.T) {
	u := &DefaultTPM12Utils{}
	symKey, err := u.NewAESCBCKey(tpm12.AlgAES128)
	if err != nil {
		t.Fatalf("NewAESCBCKey() failed: %v", err)
	}
	blockSize := aes.BlockSize

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Successful Encryption",
			data: []byte("This is a secret message."),
		},
		{
			name: "Data size equals block size",
			data: bytes.Repeat([]byte{0x01}, blockSize),
		},
		{
			name: "Data size slightly less than block size",
			data: bytes.Repeat([]byte{0x02}, blockSize-1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, keyParms, err := u.EncryptWithAES(symKey, tc.data)
			if err != nil {
				t.Errorf("EncryptWithAES(%v) returned an unexpected error: %v", tc.data, err)
			}
			if bytes.Equal(ciphertext, tc.data) && len(tc.data) > 0 {
				t.Errorf("EncryptWithAES(%v) returned ciphertext equal to plaintext, expected different", tc.data)
			}
			if keyParms.Params.SymParams == nil {
				t.Errorf("EncryptWithAES(%v) returned nil SymParams", tc.data)
			}
			if len(keyParms.Params.SymParams.IV) != blockSize {
				t.Errorf("EncryptWithAES(%v) returned IV of incorrect size: got %d, want %d", tc.data, len(keyParms.Params.SymParams.IV), blockSize)
			}

			iv := keyParms.Params.SymParams.IV
			encrypted := ciphertext

			cipherBlock, err := aes.NewCipher(symKey.Key)
			if err != nil {
				t.Fatalf("Failed to create AES cipher for decryption: %v", err)
			}

			if len(encrypted)%blockSize != 0 {
				t.Fatalf("Ciphertext is not a multiple of the block size")
			}

			decrypted := make([]byte, len(encrypted))
			encrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
			encrypter.CryptBlocks(decrypted, encrypted)

			// Remove PKCS5 padding
			if len(decrypted) == 0 {
				t.Errorf("Decrypted data is empty")
			}
			padding := int(decrypted[len(decrypted)-1])
			if padding > blockSize || padding == 0 {
				t.Errorf("Invalid padding value: %d", padding)
			}
			// Check if the padding bytes are all equal to the padding value.
			for i := 0; i < padding; i++ {
				if decrypted[len(decrypted)-1-i] != byte(padding) {
					t.Errorf("Padding bytes mismatch: expected %d, got %d at index %d", padding, decrypted[len(decrypted)-1-i], len(decrypted)-1-i)
				}
			}
			decrypted = decrypted[:len(decrypted)-padding]

			if !bytes.Equal(decrypted, tc.data) {
				t.Errorf("Decrypted data mismatch: got %v, want %v", decrypted, tc.data)
			}
		})
	}
}

func TestEncryptWithAESFailure(t *testing.T) {
	u := &DefaultTPM12Utils{}
	validSymKey, err := u.NewAESCBCKey(tpm12.AlgAES128)
	if err != nil {
		t.Fatalf("NewAESCBCKey() failed: %v", err)
	}

	invalidEncSchemeKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgAES128,
		EncScheme: EsNone, // Invalid
		Key:       bytes.Repeat([]byte{0x01}, 16),
	}
	invalidAlgIDKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgRSA, // Invalid
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x01}, 16),
	}

	testCases := []struct {
		name          string
		symKey        *TPMSymmetricKey
		data          []byte
		expectedError string
	}{
		{
			name:          "Empty Data",
			symKey:        validSymKey,
			data:          []byte{},
			expectedError: "data to encrypt cannot be empty",
		},
		{
			name:          "Invalid Symmetric Key - Wrong EncScheme",
			symKey:        invalidEncSchemeKey,
			data:          []byte("some data"),
			expectedError: "unsupported encoding scheme for symmetric key",
		},
		{
			name:          "Invalid Symmetric Key - Wrong AlgID",
			symKey:        invalidAlgIDKey,
			data:          []byte("some data"),
			expectedError: "unsupported algorithm for symmetric key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := u.EncryptWithAES(tc.symKey, tc.data)
			assertError(t, err, tc.expectedError, "EncryptWithAES")
		})
	}
}

func TestConstructAsymCAContentsSuccess(t *testing.T) {
	u := &DefaultTPM12Utils{}

	// Create a sample symmetric key
	symKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgAES128,
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x11}, 16),
	}

	// Create a sample IdentityPubKey
	identityKey := &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     tpm12.AlgRSA,
			EncScheme: EsRSAEsOAEPSHA1MGF1,
			SigScheme: SsRSASaPKCS1v15SHA1,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					KeyLength: 2048,
					NumPrimes: 2,
					Exponent:  []byte{0x01, 0x00, 0x01},
				},
			},
		},
		PubKey: TPMStorePubKey{
			KeyLength: 256,
			Key:       bytes.Repeat([]byte{0xAA}, 256),
		},
	}

	// Serialize the identityKey to compute the expected digest
	identityKeyBytes, err := u.SerializePubKey(identityKey)
	if err != nil {
		t.Fatalf("Failed to serialize identityKey: %v", err)
	}
	expectedDigest := sha1.Sum(identityKeyBytes)

	// Call the function under test
	asymCAContents, err := u.ConstructAsymCAContents(symKey, identityKey)
	if err != nil {
		t.Errorf("ConstructAsymCAContents(%+v, %+v) returned an unexpected error: %v", symKey, identityKey, err)
	}

	// Verify the results
	if !cmp.Equal(asymCAContents.SessionKey, *symKey) {
		t.Errorf("SessionKey mismatch: got %+v, want %+v", asymCAContents.SessionKey, *symKey)
	}
	if !bytes.Equal(asymCAContents.IDDigest[:], expectedDigest[:]) {
		t.Errorf("IDDigest mismatch: got %x, want %x", asymCAContents.IDDigest, expectedDigest)
	}
}

func TestConstructAsymCAContentsFailure(t *testing.T) {
	u := &DefaultTPM12Utils{}

	// Sample symmetric key and identity key for valid cases
	symKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgAES128,
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x11}, 16),
	}
	invalidAlgIDSymKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgRSA, // Invalid
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x01}, 16),
	}
	identityKey := &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID: tpm12.AlgRSA,
		},
		PubKey: TPMStorePubKey{
			KeyLength: 256,
			Key:       bytes.Repeat([]byte{0xAA}, 256),
		},
	}

	testCases := []struct {
		name          string
		symKey        *TPMSymmetricKey
		identityKey   *TPMPubKey
		expectedError string
	}{
		{
			name:          "Nil Symmetric Key",
			symKey:        nil,
			identityKey:   identityKey,
			expectedError: "nil symmetric key",
		},
		{
			name:          "Invalid Alg ID for Symmetric Key",
			symKey:        invalidAlgIDSymKey,
			identityKey:   identityKey,
			expectedError: "unsupported algorithm for symmetric key",
		},
		{
			name:          "Nil Identity Key",
			symKey:        symKey,
			identityKey:   nil,
			expectedError: "identityKey cannot be nil",
		},
		{
			name:   "SerializePubKey failure",
			symKey: symKey,
			identityKey: &TPMPubKey{
				AlgorithmParms: TPMKeyParms{
					AlgID: tpm12.AlgMGF1,
					Params: TPMParams{
						RSAParams: &TPMRSAKeyParms{},
					},
				},
			}, // RSA Params with non RSA algo will cause serialization error
			expectedError: "failed to serialize AlgorithmParms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.ConstructAsymCAContents(tc.symKey, tc.identityKey)
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("ConstructAsymCAContents: got unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("ConstructAsymCAContents: got error %v, expected error substring: %v", err, tc.expectedError)
				}
			}
		})
	}
}
func TestSerializeSymmetricKeySuccess(t *testing.T) {
	u := &DefaultTPM12Utils{}

	testCases := []struct {
		name          string
		symKey        *TPMSymmetricKey
		expectedBytes []byte
	}{
		{
			name: "AES128",
			symKey: &TPMSymmetricKey{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				Key:       bytes.Repeat([]byte{0x11}, 16),
			},
			expectedBytes: symmetricKey{key: bytes.Repeat([]byte{0x11}, 16)}.toBytes(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes, err := u.SerializeSymmetricKey(tc.symKey)
			if err != nil {
				t.Errorf("SerializeSymmetricKey(%+v) returned unexpected error: %v", tc.symKey, err)
			}
			if diff := cmp.Diff(tc.expectedBytes, gotBytes); diff != "" {
				t.Errorf("SerializeSymmetricKey(%+v) mismatch (-want +got):\n%s", tc.symKey, diff)
			}
		})
	}
}

func TestSerializeSymmetricKeyFailure(t *testing.T) {
	u := &DefaultTPM12Utils{}

	testCases := []struct {
		name          string
		symKey        *TPMSymmetricKey
		expectedError string
	}{
		{
			name:          "Nil Symmetric Key",
			symKey:        nil,
			expectedError: "nil symmetric key",
		},
		{
			name: "Invalid AlgID",
			symKey: &TPMSymmetricKey{
				AlgID:     tpm12.AlgRSA, // Invalid
				EncScheme: EsSymCBCPKCS5,
				Key:       bytes.Repeat([]byte{0x11}, 16),
			},
			expectedError: "unsupported algorithm for symmetric key: RSA",
		},
		{
			name: "Invalid EncScheme",
			symKey: &TPMSymmetricKey{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsNone, // Invalid
				Key:       bytes.Repeat([]byte{0x11}, 16),
			},
			expectedError: "invalid symmetric key: unsupported encoding scheme for symmetric key",
		},
		{
			name: "Key too large",
			symKey: &TPMSymmetricKey{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				Key:       bytes.Repeat([]byte{0x11}, math.MaxUint16+1),
			},
			expectedError: "symmetric key data size (65536) exceeds maximum UINT16 size",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.SerializeSymmetricKey(tc.symKey)
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("SerializeSymmetricKey: got unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("SerializeSymmetricKey: got error %v, expected error substring: %v", err, tc.expectedError)
				}
			}
		})
	}
}

func TestSerializeAsymCAContentsSuccess(t *testing.T) {
	u := &DefaultTPM12Utils{}
	symKey := &TPMSymmetricKey{
		AlgID:     tpm12.AlgAES128,
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x11}, 16),
	}
	idDigest := [20]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	}
	asymCAContents := &TPMAsymCAContents{
		SessionKey: *symKey,
		IDDigest:   idDigest,
	}

	// Manually construct expected bytes
	sessionKeyBytes, err := u.SerializeSymmetricKey(symKey)
	if err != nil {
		t.Fatalf("Failed to serialize symmetric key for test setup: %v", err)
	}
	var expectedBuf bytes.Buffer
	expectedBuf.Write(sessionKeyBytes)
	expectedBuf.Write(idDigest[:])
	expectedBytes := expectedBuf.Bytes()

	gotBytes, err := u.SerializeAsymCAContents(asymCAContents)
	if err != nil {
		t.Errorf("SerializeAsymCAContents(%+v) returned unexpected error: %v", asymCAContents, err)
	}

	if diff := cmp.Diff(expectedBytes, gotBytes); diff != "" {
		t.Errorf("SerializeAsymCAContents(%+v) mismatch (-want +got):\n%s", asymCAContents, diff)
	}
}

func TestSerializeAsymCAContentsFailure(t *testing.T) {
	u := &DefaultTPM12Utils{}
	validIDDigest := [20]byte{}

	invalidSymKeyAlg := &TPMSymmetricKey{
		AlgID:     tpm12.AlgRSA, // Invalid AlgID
		EncScheme: EsSymCBCPKCS5,
		Key:       bytes.Repeat([]byte{0x11}, 16),
	}
	testCases := []struct {
		name           string
		asymCAContents *TPMAsymCAContents
		expectedError  string
	}{
		{
			name:           "Nil AsymCAContents",
			asymCAContents: nil,
			expectedError:  "asymCAContents cannot be nil",
		},
		{
			name: "Invalid SessionKey - Serialization Failure",
			asymCAContents: &TPMAsymCAContents{
				SessionKey: *invalidSymKeyAlg,
				IDDigest:   validIDDigest,
			},
			expectedError: "unsupported algorithm for symmetric key: RSA",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.SerializeAsymCAContents(tc.asymCAContents)
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("SerializeAsymCAContents: got unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("SerializeAsymCAContents: got error %v, expected error substring: %v", err, tc.expectedError)
				}
			}
		})
	}
}

type tpmPubKeyOptions struct {
	algID     *tpm12.Algorithm
	exponent  *[]byte
	modulus   *[]byte
	sigScheme *TPMSignatureScheme
}

func (opts tpmPubKeyOptions) build() *TPMPubKey {
	algID := tpm12.AlgRSA
	if opts.algID != nil {
		algID = *opts.algID
	}

	exponent := []byte{} // Default empty exponent
	if opts.exponent != nil {
		exponent = *opts.exponent
	}

	modulus := []byte{0x01, 0x02, 0x03} // Default modulus
	if opts.modulus != nil {
		modulus = *opts.modulus
	}

	sigScheme := SsRSASaPKCS1v15SHA1 // Default signature scheme
	if opts.sigScheme != nil {
		sigScheme = *opts.sigScheme
	}

	return &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     algID,
			SigScheme: sigScheme,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					Exponent: exponent,
				},
			},
		},
		PubKey: TPMStorePubKey{
			Key: modulus,
		},
	}
}

func TestTpmPubKeyToRSAPubKey_Success(t *testing.T) {
	testCases := []struct {
		name     string
		opts     tpmPubKeyOptions
		expected *rsa.PublicKey
	}{
		{
			name: "Valid TPMPubKey with default exponent",
			opts: tpmPubKeyOptions{
				modulus: &[]byte{0x01, 0x02, 0x03},
			},
			expected: &rsa.PublicKey{
				N: new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03}),
				E: 65537,
			},
		},
		{
			name: "Valid TPMPubKey with specific exponent",
			opts: tpmPubKeyOptions{
				exponent: &[]byte{0x03},
				modulus:  &[]byte{0x0A, 0x0B, 0x0C},
			},
			expected: &rsa.PublicKey{
				N: new(big.Int).SetBytes([]byte{0x0A, 0x0B, 0x0C}),
				E: 3,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			tpmPubKey := tc.opts.build()
			rsaPubKey, err := u.TpmPubKeyToRSAPubKey(tpmPubKey)
			if err != nil {
				t.Fatalf("TpmPubKeyToRSAPubKey(%+v) returned unexpected error: %v", tpmPubKey, err)
			}
			if diff := cmp.Diff(tc.expected, rsaPubKey); diff != "" {
				t.Errorf("TpmPubKeyToRSAPubKey(%+v) mismatch (-want +got):\n%s", tpmPubKey, diff)
			}
		})
	}
}

func TestTpmPubKeyToRSAPubKey_Failure(t *testing.T) {
	aesAlg := tpm12.AlgAES128
	testCases := []struct {
		name          string
		tpmPubKey     *TPMPubKey
		expectedError string
	}{
		{
			name:          "Nil TPMPubKey",
			tpmPubKey:     nil,
			expectedError: "pubKey is nil",
		},
		{
			name: "Not RSA Algorithm",
			tpmPubKey: tpmPubKeyOptions{
				algID: &aesAlg,
			}.build(),
			expectedError: "unsupported algorithm",
		},
		{
			name: "Nil RSA Params",
			tpmPubKey: &TPMPubKey{
				AlgorithmParms: TPMKeyParms{
					AlgID: tpm12.AlgRSA,
					Params: TPMParams{
						RSAParams: nil, // Missing RSA params
					},
				},
			},
			expectedError: "RSA params are nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			_, err := u.TpmPubKeyToRSAPubKey(tc.tpmPubKey)
			if err == nil {
				t.Fatalf("TpmPubKeyToRSAPubKey(%+v) got nil error, want error containing %q", tc.tpmPubKey, tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("TpmPubKeyToRSAPubKey(%+v) got error %v, want error containing %q", tc.tpmPubKey, err, tc.expectedError)
			}
		})
	}
}

func TestVerifySignatureWithRSAKey_Success(t *testing.T) {
	u := &DefaultTPM12Utils{}
	ctx := context.Background()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	tpmPubKey, err := u.ConstructPubKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to construct TPMPubKey: %v", err)
	}

	data := []byte("test data")
	// SHA1 digest
	hashedSHA1 := sha1.Sum(data)

	// Signature with PKCS1v15 SHA1
	signatureSHA1, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, hashedSHA1[:])
	if err != nil {
		t.Fatalf("Failed to sign with SHA1: %v", err)
	}

	// Signature with PKCS1v15 DER (no hashing before signing)
	signatureDER, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), data)
	if err != nil {
		t.Fatalf("Failed to sign with DER: %v", err)
	}

	testCases := []struct {
		name      string
		sigScheme TPMSignatureScheme
		signature []byte
		digest    []byte
	}{
		{
			name:      "Valid PKCS1v15 SHA1",
			sigScheme: SsRSASaPKCS1v15SHA1,
			signature: signatureSHA1,
			digest:    hashedSHA1[:],
		},
		{
			name:      "Valid PKCS1v15 DER",
			sigScheme: SsRSASaPKCS1v15DER,
			signature: signatureDER,
			digest:    data, // For DER, the digest is the original data
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentPubKey := *tpmPubKey
			currentPubKey.AlgorithmParms.SigScheme = tc.sigScheme

			valid, err := u.VerifySignatureWithRSAKey(ctx, &currentPubKey, tc.signature, tc.digest)
			if err != nil {
				t.Errorf("VerifySignatureWithRSAKey() returned unexpected error: %v", err)
			}
			if !valid {
				t.Errorf("VerifySignatureWithRSAKey() returned false, want true")
			}
		})
	}
}

func TestVerifySignatureWithRSAKey_Failure(t *testing.T) {
	u := &DefaultTPM12Utils{}
	ctx := context.Background()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	baseTpmPubKey, err := u.ConstructPubKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to construct TPMPubKey: %v", err)
	}

	data := []byte("test data")
	hashedSHA1 := sha1.Sum(data)
	badSignature := []byte("bad signature")

	noneScheme := SsNone
	sha1Scheme := SsRSASaPKCS1v15SHA1
	derScheme := SsRSASaPKCS1v15DER

	testCases := []struct {
		name          string
		pubKey        *TPMPubKey
		signature     []byte
		digest        []byte
		expectedError string
	}{
		{
			name:          "Invalid TPMPubKey",
			pubKey:        &TPMPubKey{}, // Invalid empty key
			signature:     []byte{},
			digest:        []byte{},
			expectedError: "failed to parse TPM public key: unsupported algorithm: unknown_algorithm",
		},
		{
			name: "Unsupported Signature Scheme",
			pubKey: tpmPubKeyOptions{
				modulus:   &baseTpmPubKey.PubKey.Key,
				exponent:  &baseTpmPubKey.AlgorithmParms.Params.RSAParams.Exponent,
				sigScheme: &noneScheme,
			}.build(),
			signature:     []byte{},
			digest:        []byte{},
			expectedError: "unsupported signature scheme: 1",
		},
		{
			name: "Invalid Signature PKCS1v15 SHA1",
			pubKey: tpmPubKeyOptions{
				modulus:   &baseTpmPubKey.PubKey.Key,
				exponent:  &baseTpmPubKey.AlgorithmParms.Params.RSAParams.Exponent,
				sigScheme: &sha1Scheme,
			}.build(),
			signature:     badSignature,
			digest:        hashedSHA1[:],
			expectedError: "invalid PKCS1v15 signature for scheme 2: crypto/rsa: verification error",
		},
		{
			name: "Invalid Signature PKCS1v15 DER",
			pubKey: tpmPubKeyOptions{
				modulus:   &baseTpmPubKey.PubKey.Key,
				exponent:  &baseTpmPubKey.AlgorithmParms.Params.RSAParams.Exponent,
				sigScheme: &derScheme,
			}.build(),
			signature:     badSignature,
			digest:        data, // For DER, the digest is the original data
			expectedError: "invalid PKCS1v15 signature for scheme 3: crypto/rsa: verification error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.VerifySignatureWithRSAKey(ctx, tc.pubKey, tc.signature, tc.digest)
			if err == nil {
				t.Fatalf("VerifySignatureWithRSAKey() got nil error, want error containing %q", tc.expectedError)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Errorf("VerifySignatureWithRSAKey() got error %v, want error containing %q", err, tc.expectedError)
			}
		})
	}
}

func TestEncryptWithPublicKey_Success(t *testing.T) {
	// Generate a sample RSA key pair for testing.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	sampleData := []byte("test data to encrypt")

	u := &DefaultTPM12Utils{}
	encryptedData, err := u.EncryptWithPublicKey(context.Background(), publicKey, sampleData, tpm12.AlgRSA, EsRSAEsOAEPSHA1MGF1)
	if err != nil {
		t.Fatalf("EncryptWithPublicKey(%v, %v, %v) failed: %v", publicKey, sampleData, EsRSAEsOAEPSHA1MGF1, err)
	}
	// the label "TCPA" encoded in UTF-16BE for RSAES-OAEP.
	label := []byte(tpmLabel)
	// #nosec
	decryptedData, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, encryptedData, label)
	if err != nil {
		t.Fatalf("rsa.DecryptOAEP failed: %v", err)
	}
	if !cmp.Equal(decryptedData, sampleData) {
		t.Errorf("DecryptOAEP() = %v, want %v", decryptedData, sampleData)
	}
}

func TestEncryptWithPublicKey_Failure(t *testing.T) {
	// Generate a sample RSA key pair for testing.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	sampleData := []byte("test data to encrypt")

	testCases := []struct {
		name          string
		publicKey     *rsa.PublicKey
		algo          tpm12.Algorithm
		encScheme     TPMEncodingScheme
		sampleData    []byte
		expectedError string
	}{
		{
			name:          "Nil publicKey",
			publicKey:     nil,
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsOAEPSHA1MGF1,
			expectedError: "publicKey or its modulus cannot be nil",
		},
		{
			name:          "Empty data",
			publicKey:     publicKey,
			sampleData:    []byte{},
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsOAEPSHA1MGF1,
			expectedError: "data is nil or empty",
		},
		{
			name:          "Nil publicKey modulus",
			publicKey:     &rsa.PublicKey{},
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsOAEPSHA1MGF1,
			expectedError: "publicKey or its modulus cannot be nil",
		},
		{
			name: "Zero size publicKey",
			publicKey: &rsa.PublicKey{
				N: big.NewInt(0),
				E: 0,
			},
			algo:          tpm12.AlgRSA,
			encScheme:     EsRSAEsOAEPSHA1MGF1,
			expectedError: "publicKey size cannot be zero",
		},
		{
			name:          "Unsupported algorithm",
			publicKey:     publicKey,
			algo:          tpm12.AlgAES128,
			encScheme:     EsRSAEsPKCSv15,
			expectedError: "unsupported algorithm",
		},
		{
			name:          "Unsupported encoding scheme",
			publicKey:     publicKey,
			algo:          tpm12.AlgRSA,
			encScheme:     EsSymCBCPKCS5,
			expectedError: "unsupported encoding scheme",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			data := sampleData
			if tc.sampleData != nil {
				data = tc.sampleData
			}
			_, err := u.EncryptWithPublicKey(context.Background(), tc.publicKey, data, tc.algo, tc.encScheme)
			assertError(t, err, tc.expectedError, "EncryptWithPublicKey")
		})
	}
}
