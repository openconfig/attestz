package biz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	// #nosec
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	tpm12 "github.com/google/go-tpm/tpm"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

// TODO: refactor tests to split success and failure cases, and make create bytes helpers more readable.
// createSymmetricKeyParmsBytes creates a byte slice representing a TPMSymmetricKeyParms structure.
func createSymmetricKeyParmsBytes(keyLength, blockSize, ivSize uint32, iv []byte) []byte {
	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, keyLength)
	binaryWriteUint32(buffer, blockSize)
	binaryWriteUint32(buffer, ivSize)
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

func TestParseSymmetricKeyParms(t *testing.T) {
	// Valid cases
	testCases := []struct {
		name          string
		keyLength     uint32
		blockSize     uint32
		ivSize        uint32
		iv            []byte
		expectedError string
	}{
		{
			name:          "Valid params",
			keyLength:     16,
			blockSize:     16,
			ivSize:        16,
			iv:            make([]byte, 16),
			expectedError: "",
		},
		{
			name:          "invalid zero IV",
			keyLength:     16,
			blockSize:     16,
			ivSize:        0,
			iv:            []byte{},
			expectedError: "failed to read ivSize: read uint32 is zero, expected non-zero",
		},
		{
			name:          "Invalid zero keyLength",
			keyLength:     0,
			blockSize:     16,
			ivSize:        16,
			iv:            make([]byte, 16),
			expectedError: "failed to read keyLength",
		},
		{
			name:          "Invalid zero blockSize",
			keyLength:     16,
			blockSize:     0,
			ivSize:        16,
			iv:            make([]byte, 16),
			expectedError: "failed to read blockSize",
		},
		{
			name:          "Invalid ivSize too small",
			keyLength:     16,
			blockSize:     16,
			ivSize:        8,
			iv:            make([]byte, 16),
			expectedError: "leftover bytes in TPM_SYMMETRIC_KEY_PARMS block",
		},
		{
			name:          "Invalid ivSize bigger than iv",
			keyLength:     16,
			blockSize:     16,
			ivSize:        32,
			iv:            make([]byte, 16),
			expectedError: "failed to read IV",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := createSymmetricKeyParmsBytes(tc.keyLength, tc.blockSize, tc.ivSize, tc.iv)
			u := &DefaultTPM12Utils{}
			result, err := u.ParseSymmetricKeyParms(data)

			assertError(t, err, tc.expectedError, "ParseSymmetricKeyParms")

			if tc.expectedError == "" {
				if result.KeyLength != tc.keyLength {
					t.Errorf("KeyLength mismatch: got %v, expected %v", result.KeyLength, tc.keyLength)
				}
				if result.BlockSize != tc.blockSize {
					t.Errorf("BlockSize mismatch: got %v, expected %v", result.BlockSize, tc.blockSize)
				}
				if result.IV == nil && tc.ivSize != 0 {
					t.Errorf("IV mismatch: got nil, expected %v", tc.iv)
				}
				if tc.ivSize != 0 && !cmp.Equal(result.IV, tc.iv) {
					t.Errorf("IV mismatch: got %v, expected %v", result.IV, tc.iv)
				}
			}
		})
	}
}

func createRSAKeyParmsBytes(keyLength, numPrimes, exponentSize uint32, exponent []byte) []byte {
	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, keyLength)
	binaryWriteUint32(buffer, numPrimes)
	binaryWriteUint32(buffer, exponentSize)
	buffer.Write(exponent)
	return buffer.Bytes()
}

func TestParseRSAKeyParms(t *testing.T) {
	// Valid cases
	testCases := []struct {
		name          string
		keyLength     uint32
		numPrimes     uint32
		exponentSize  uint32
		exponent      []byte
		input         []byte
		expectedError string
	}{
		{
			name:          "Valid params",
			keyLength:     2048,
			numPrimes:     2,
			exponentSize:  3,
			exponent:      []byte{1, 2, 3},
			expectedError: "",
		},
		{
			name:          "Invalid zero keyLength",
			keyLength:     0,
			numPrimes:     2,
			exponentSize:  3,
			exponent:      []byte{1, 2, 3},
			expectedError: "failed to read keyLength: read uint32 is zero, expected non-zero",
		},
		{
			name:          "Invalid zero numPrimes",
			keyLength:     2048,
			numPrimes:     0,
			exponentSize:  3,
			exponent:      []byte{1, 2, 3},
			expectedError: "failed to read numPrimes: read uint32 is zero, expected non-zero",
		},
		{
			name:          "Invalid exponentSize too big",
			keyLength:     2048,
			numPrimes:     2,
			exponentSize:  257,
			exponent:      make([]byte, 256),
			expectedError: "failed to read exponent",
		},
		{
			name:          "Invalid exponentSize too small",
			keyLength:     2048,
			numPrimes:     2,
			exponentSize:  2,
			exponent:      make([]byte, 3),
			expectedError: "leftover bytes in TPM_RSA_KEY_PARMS block",
		},
		{
			name:          "Not enough bytes",
			input:         createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2}),
			expectedError: "failed to read exponent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.input
			if data == nil {
				data = createRSAKeyParmsBytes(tc.keyLength, tc.numPrimes, tc.exponentSize, tc.exponent)
			}
			u := &DefaultTPM12Utils{}
			result, err := u.ParseRSAKeyParms(data)

			assertError(t, err, tc.expectedError, "ParseRSAKeyParms")

			if tc.expectedError == "" {
				if result.KeyLength != tc.keyLength {
					t.Errorf("KeyLength mismatch: got %v, expected %v", result.KeyLength, tc.keyLength)
				}
				if result.NumPrimes != tc.numPrimes {
					t.Errorf("numPrimes mismatch: got %v, expected %v", result.NumPrimes, tc.numPrimes)
				}
				if !cmp.Equal(result.Exponent, tc.exponent) {
					t.Errorf("Exponent mismatch: got %v, expected %v", result.Exponent, tc.exponent)
				}
			}
		})
	}
}

// createKeyParmsBytes creates a byte slice representing a TPM_KEY_PARMS structure.
func createKeyParmsBytes(algID tpm12.Algorithm, encScheme TPMEncodingScheme, sigScheme TPMSignatureScheme, parms []byte) []byte {
	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, uint32(algID))
	binaryWriteUint16(buffer, uint16(encScheme))
	binaryWriteUint16(buffer, uint16(sigScheme))
	binaryWriteUint32(buffer, uint32(len(parms))) // paramSize
	buffer.Write(parms)
	return buffer.Bytes()
}

func TestParseKeyParmsFromReader(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expected      *TPMKeyParms
		expectedError string
	}{
		{
			name: "Valid RSA KeyParms",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}),
			),
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
			expectedError: "",
		},
		{
			name: "Valid Symmetric KeyParms (AES128)",
			input: createKeyParmsBytes(
				tpm12.AlgAES128, EsSymCBCPKCS5, SsNone, createSymmetricKeyParmsBytes(16, 16, 16, make([]byte, 16)),
			),
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
			expectedError: "",
		},
		{
			name: "Valid KeyParms with no specific params (SHA1)",
			input: createKeyParmsBytes(
				tpm12.AlgSHA, EsNone, SsNone, []byte{}, // No params
			),
			expected: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params:    TPMParams{}, // Should be empty
			},
			expectedError: "",
		},
		{
			name:          "Input too short for AlgID",
			input:         []byte{1, 2, 3}, // 3 bytes, needs 4 for AlgID
			expectedError: "failed to read algorithmID",
		},
		{
			name:          "Invalid AlgID",
			input:         []byte{1, 2, 3, 4},
			expectedError: "invalid algorithmID",
		},
		{
			name: "Input too short for EncScheme",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}),
			)[:4], // Truncate after AlgID
			expectedError: "failed to read encScheme",
		},
		{
			name: "Input too short for SigScheme",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}),
			)[:6], // Truncate after EncScheme
			expectedError: "failed to read sigScheme",
		},
		{
			name: "Input too short for ParamSize",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}),
			)[:8], // Truncate after SigScheme
			expectedError: "failed to read paramSize",
		},
		{
			name: "ParamSize too small for RSA params",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, []byte{1, 2}, // ParamSize will be 2, but RSA params need at least 4 bytes for KeyLength
			),
			expectedError: "failed to parse RSA key parms",
		},
		{
			name: "Input too short for Parms data",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}),
			)[:14], // Truncate in the middle of parms
			expectedError: "failed to read parms", // Error from readBytes
		},
		{
			name: "Invalid RSA Parms (zero keyLength)",
			input: createKeyParmsBytes(
				tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(0, 2, 3, []byte{1, 2, 3}),
			),
			expectedError: "failed to parse RSA key parms: failed to read keyLength: read uint32 is zero, expected non-zero",
		},
		{
			name: "Invalid Symmetric Parms (zero ivSize)",
			input: createKeyParmsBytes(
				tpm12.AlgAES128, EsSymCBCPKCS5, SsNone, createSymmetricKeyParmsBytes(16, 16, 0, []byte{}),
			),
			expectedError: "failed to parse Symmetric key parms: failed to read ivSize: read uint32 is zero, expected non-zero",
		},
		{
			name: "Unexpected paramSize for SHA1 (no params expected)",
			input: createKeyParmsBytes(
				tpm12.AlgSHA, EsNone, SsNone, []byte{1, 2, 3}, // Should be empty, but has data
			),
			expectedError: "unexpected params size for algorithm SHA1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			u := &DefaultTPM12Utils{}
			result, err := u.ParseKeyParmsFromReader(reader)

			assertError(t, err, tc.expectedError, "ParseKeyParms")

			if tc.expectedError == "" {
				if !cmp.Equal(result, tc.expected) {
					t.Errorf("ParseKeyParms mismatch:\nGot: %+v\nExpected: %+v", result, tc.expected)
				}
			}
		})
	}
}

// IdentityRequestOptions provides options for creating TPMIdentityReq bytes.
// Fields, if nil or empty, will use default values.
type IdentityRequestOptions struct {
	AsymBlobSize *uint32
	SymBlobSize  *uint32
	AsymKeyParms []byte
	SymKeyParms  []byte
	AsymBlob     []byte
	SymBlob      []byte
}

// createIdentityRequestBytes creates a byte slice representing a TPM_IDENTITY_REQ structure
// based on the provided options. Default values are used for any unset fields.
func createIdentityRequestBytes(opts IdentityRequestOptions) []byte {
	// Apply defaults if not provided.
	asymBlobSize := uint32(10)
	if opts.AsymBlobSize != nil {
		asymBlobSize = *opts.AsymBlobSize
	}
	symBlobSize := uint32(16)
	if opts.SymBlobSize != nil {
		symBlobSize = *opts.SymBlobSize
	}
	asymKeyParms := createKeyParmsBytes(tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(2048, 2, 3, []byte{1, 2, 3}))
	if opts.AsymKeyParms != nil {
		asymKeyParms = opts.AsymKeyParms
	}
	symKeyParms := createKeyParmsBytes(tpm12.AlgAES128, EsSymCBCPKCS5, SsNone, createSymmetricKeyParmsBytes(16, 16, 16, make([]byte, 16)))
	if opts.SymKeyParms != nil {
		symKeyParms = opts.SymKeyParms
	}
	asymBlob := make([]byte, asymBlobSize)
	if opts.AsymBlob != nil {
		asymBlob = opts.AsymBlob
	}
	symBlob := make([]byte, symBlobSize)
	if opts.SymBlob != nil {
		symBlob = opts.SymBlob
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
			input: createIdentityRequestBytes(IdentityRequestOptions{}), // Use all defaults
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
			input: createIdentityRequestBytes(IdentityRequestOptions{
				AsymBlobSize: ptrUint32(0),
				AsymBlob:     []byte{},
			}),
			expectedError: "failed to read asymBlobSize: read uint32 is zero, expected non-zero",
		},
		{
			name: "invalid request with no symblob",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				SymBlobSize: ptrUint32(0),
				SymBlob:     []byte{},
			}),
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
			input: createIdentityRequestBytes(IdentityRequestOptions{
				AsymKeyParms: []byte{1, 2, 3}, // Invalid asymKeyParms
			}),
			expectedError: "failed to parse asymAlgorithm (TPM_KEY_PARMS): invalid algorithmID",
		},
		{
			name: "Input too short for symAlgorithm",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				SymKeyParms: []byte{1, 2, 3}, // Invalid symKeyParms
			}),
			expectedError: "failed to parse symAlgorithm (TPM_KEY_PARMS): invalid algorithmID",
		},
		{
			name: "Input too short for asymBlob",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				AsymBlobSize: ptrUint32(10),
				AsymBlob:     make([]byte, 5),
			}),
			expectedError: "failed to read symBlob",
		},
		{
			name: "Input too short for symBlob",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				SymBlobSize: ptrUint32(10),
				SymBlob:     make([]byte, 5),
			}),
			expectedError: "failed to read symBlob",
		},
		{
			name: "Invalid asymKeyParms (zero keyLength)",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				AsymKeyParms: createKeyParmsBytes(tpm12.AlgRSA, EsRSAEsPKCSv15, SsRSASaPKCS1v15SHA1, createRSAKeyParmsBytes(0, 2, 3, []byte{1, 2, 3})),
			}),
			expectedError: "failed to parse asymAlgorithm (TPM_KEY_PARMS): failed to parse RSA key parms",
		},
		{
			name: "Invalid symKeyParms (zero ivSize)",
			input: createIdentityRequestBytes(IdentityRequestOptions{
				SymKeyParms: createKeyParmsBytes(tpm12.AlgAES128, EsSymCBCPKCS5, SsNone, createSymmetricKeyParmsBytes(16, 16, 0, []byte{})),
			}),
			expectedError: "failed to parse symAlgorithm (TPM_KEY_PARMS): failed to parse Symmetric key parms",
		},
		{
			name:          "leftover bytes",
			input:         append(createIdentityRequestBytes(IdentityRequestOptions{}), 1, 2, 3),
			expectedError: "leftover bytes in TPM_IDENTITY_REQ after parsing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &DefaultTPM12Utils{}
			_, err := u.ParseIdentityRequest(tc.input)
			assertError(t, err, tc.expectedError, "ParseIdentityRequest")
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

// createSymmetricKeyBytes creates a byte slice representing a TPMSymmetricKey structure.
func createSymmetricKeyBytes(key []byte) []byte {
	buffer := new(bytes.Buffer)
	binaryWriteUint32(buffer, uint32(tpm12.AlgAES128))
	binaryWriteUint16(buffer, uint16(EsSymCBCPKCS5))
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
			name:  "Valid key",
			input: createSymmetricKeyBytes([]byte{1, 2, 3, 4}),
			expected: &TPMSymmetricKey{
				AlgID:     tpm12.AlgAES128,
				EncScheme: EsSymCBCPKCS5,
				Key:       []byte{1, 2, 3, 4},
			},
			expectedError: "",
		},
		{
			name:          "Invalid empty key",
			input:         createSymmetricKeyBytes([]byte{}),
			expectedError: "key cannot be empty",
		},
		{
			name:          "Input too short for AlgID",
			input:         []byte{1, 2, 3},
			expectedError: "failed to read algorithmID",
		},
		{
			name:          "Invalid AlgID",
			input:         []byte{1, 2, 3, 4},
			expectedError: "invalid algorithmID",
		},
		{
			name:          "Input too short for EncScheme",
			input:         createSymmetricKeyBytes([]byte{1, 2, 3, 4})[:4],
			expectedError: "failed to read encScheme",
		},
		{
			name:          "Input too short for keySize",
			input:         createSymmetricKeyBytes([]byte{1, 2, 3, 4})[:6],
			expectedError: "failed to read keySize",
		},
		{
			name:          "Input too short for key data",
			input:         createSymmetricKeyBytes([]byte{1, 2, 3, 4})[:10], // 4+2+2+2 bytes
			expectedError: "failed to read key (size 4)",
		},
		{
			name:          "Leftover bytes",
			input:         append(createSymmetricKeyBytes([]byte{1, 2, 3, 4}), 0xDE, 0xAD, 0xBE, 0xEF),
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

func TestSerializeKeyParms(t *testing.T) {
	u := &DefaultTPM12Utils{}
	rsaParamsBytes, err := u.SerializeRSAKeyParms(&TPMRSAKeyParms{KeyLength: 2048, NumPrimes: 2, Exponent: []byte{0x01, 0x00, 0x01}})
	if err != nil {
		t.Fatalf("SerializeRSAKeyParms returned unexpected error: %v", err)
	}
	symParamsBytes, err := u.SerializeSymmetricKeyParms(&TPMSymmetricKeyParms{KeyLength: 16, BlockSize: 16, IV: make([]byte, 16)})
	if err != nil {
		t.Fatalf("SerializeSymmetricKeyParms returned unexpected error: %v", err)
	}

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
			expectedBytes: append(
				[]byte{
					0x00, 0x00, 0x00, 0x01, // AlgID (tpm12.AlgRSA)
					0x00, 0x02, // EncScheme (EsRSAEsPKCSv15)
					0x00, 0x02, // SigScheme (SsRSASaPKCS1v15SHA1)
					0x00, 0x00, 0x00, 0x0f, // ParamSize (len of rsaParamsBytes)
				},
				rsaParamsBytes...,
			),
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
			expectedBytes: append(
				[]byte{
					0x00, 0x00, 0x00, 0x06, // AlgID (tpm12.AlgAES128)
					0x00, 0xff, // EncScheme (EsSymCBCPKCS5)
					0x00, 0x01, // SigScheme (SsNone)
					0x00, 0x00, 0x00, 0x1c, // ParamSize (len of symParamsBytes)
				},
				symParamsBytes...,
			),
		},
		{
			name: "KeyParms with No Params",
			keyParms: &TPMKeyParms{
				AlgID:     tpm12.AlgSHA,
				EncScheme: EsNone,
				SigScheme: SsNone,
				Params:    TPMParams{},
			},
			expectedBytes: []byte{
				0x00, 0x00, 0x00, 0x04, // AlgID (tpm12.AlgSHA)
				0x00, 0x01, // EncScheme (EsNone)
				0x00, 0x01, // SigScheme (SsNone)
				0x00, 0x00, 0x00, 0x00, // ParamSize (0)
			},
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
	keyParmsBytes, err := u.SerializeKeyParms(&tpmPubKey.AlgorithmParms)
	if err != nil {
		t.Fatalf("SerializeKeyParms returned unexpected error: %v", err)
	}
	pubKeyBytes, err := u.SerializeStorePubKey(&tpmPubKey.PubKey)
	if err != nil {
		t.Fatalf("SerializeStorePubKey returned unexpected error: %v", err)
	}

	expectedBytes := append(keyParmsBytes, pubKeyBytes...)

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

// CreateStorePubKeyBytesOptions provides options for creating TPM_STORE_PUBKEY bytes.
type CreateStorePubKeyBytesOptions struct {
	Key       []byte
	KeyLength *uint32
}

// createStorePubKeyBytes creates a byte slice representing a TPM_STORE_PUBKEY structure.
func createStorePubKeyBytes(opts CreateStorePubKeyBytesOptions) []byte {
	buffer := new(bytes.Buffer)
	key := opts.Key
	if key == nil {
		key = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} // Default key
	}

	var keyLength uint32
	if opts.KeyLength != nil {
		keyLength = *opts.KeyLength
	} else {
		keyLength = uint32(len(key))
	}
	// Write the keyLength to the buffer.
	binaryWriteUint32(buffer, keyLength)
	buffer.Write(key)
	return buffer.Bytes()
}

// CreatePubKeyBytesOptions provides options for creating TPM_PUBKEY bytes.
type CreatePubKeyBytesOptions struct {
	AlgID     *tpm12.Algorithm
	EncScheme *TPMEncodingScheme
	SigScheme *TPMSignatureScheme
	Parms     []byte
	PubKey    []byte
	PubKeyLen *uint32
}

// createPubKeyBytes creates a byte slice representing a TPM_PUBKEY structure.
func createPubKeyBytes(opts CreatePubKeyBytesOptions) []byte {
	buffer := new(bytes.Buffer)
	aik := defaultTestAik()

	algID := aik.AlgorithmParms.AlgID
	if opts.AlgID != nil {
		algID = *opts.AlgID
	}
	encScheme := aik.AlgorithmParms.EncScheme
	if opts.EncScheme != nil {
		encScheme = *opts.EncScheme
	}
	sigScheme := aik.AlgorithmParms.SigScheme
	if opts.SigScheme != nil {
		sigScheme = *opts.SigScheme
	}
	parms := createRSAKeyParmsBytes(
		aik.AlgorithmParms.Params.RSAParams.KeyLength,
		aik.AlgorithmParms.Params.RSAParams.NumPrimes,
		uint32(len(aik.AlgorithmParms.Params.RSAParams.Exponent)),
		aik.AlgorithmParms.Params.RSAParams.Exponent,
	)
	if opts.Parms != nil {
		parms = opts.Parms
	}

	buffer.Write(createKeyParmsBytes(algID, encScheme, sigScheme, parms))
	if opts.PubKey != nil || opts.PubKeyLen != nil {
		buffer.Write(createStorePubKeyBytes(CreateStorePubKeyBytesOptions{Key: opts.PubKey, KeyLength: opts.PubKeyLen}))
	} else {
		buffer.Write(createStorePubKeyBytes(CreateStorePubKeyBytesOptions{Key: aik.PubKey.Key, KeyLength: &aik.PubKey.KeyLength}))
	}
	return buffer.Bytes()
}

func TestParseStorePubKeyFromReader_Success(t *testing.T) {
	testCases := []struct {
		name     string
		options  CreateStorePubKeyBytesOptions
		expected *TPMStorePubKey
	}{
		{
			name:    "Valid TPMStorePubKey",
			options: CreateStorePubKeyBytesOptions{},
			expected: &TPMStorePubKey{
				KeyLength: 10,
				Key:       []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(createStorePubKeyBytes(tc.options))
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
			input:         createStorePubKeyBytes(CreateStorePubKeyBytesOptions{KeyLength: ptrUint32(15)}),
			expectedError: "failed to read key",
		},
		{
			name:          "Zero KeyLength",
			input:         createStorePubKeyBytes(CreateStorePubKeyBytesOptions{KeyLength: ptrUint32(0)}),
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
	defaultOpts := CreatePubKeyBytesOptions{}

	testCases := []struct {
		name     string
		input    []byte
		expected *TPMPubKey
	}{
		{
			name:  "Valid TPMPubKey",
			input: createPubKeyBytes(defaultOpts),
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
			input: createPubKeyBytes(CreatePubKeyBytesOptions{
				Parms: []byte{1}, // Invalid parms
			}),
			expectedError: "failed to parse AlgorithmParms",
		},
		{
			name: "Input too short for AlgorithmParms",
			input: createPubKeyBytes(CreatePubKeyBytesOptions{
				Parms: []byte{1, 2, 3, 4, 5},
			}),
			expectedError: "failed to parse AlgorithmParms",
		},
		{
			name: "Input too short for PubKey",
			input: createPubKeyBytes(CreatePubKeyBytesOptions{
				PubKey:    []byte{1, 2, 3, 4, 5},
				PubKeyLen: ptrUint32(10),
			}),
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

func TestNewAESGCMKeySuccess(t *testing.T) {
	tests := []struct {
		name string
		algo tpm12.Algorithm
	}{
		{
			name: "AES128",
			algo: tpm12.AlgAES128,
		},
		{
			name: "AES256",
			algo: tpm12.AlgAES256,
		},
	}

	u := &DefaultTPM12Utils{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kh, keyBytes, err := u.NewAESGCMKey(test.algo)
			if err != nil {
				t.Fatalf("NewAESGCMKey(%v) failed: %v", test.algo, err)
			}
			if kh == nil {
				t.Errorf("NewAESGCMKey(%v) returned nil keyset handle", test.algo)
			}
			if len(keyBytes) == 0 {
				t.Errorf("NewAESGCMKey(%v) returned empty key bytes", test.algo)
			}

			// Verify that the keyBytes can be read back into a keyset handle.
			reader := bytes.NewReader(keyBytes)
			_, err = insecurecleartextkeyset.Read(keyset.NewBinaryReader(reader))
			if err != nil {
				t.Errorf("Failed to read keyset from binary bytes: %v", err)
			}
		})
	}
}

func TestNewAESGCMKeyFailure(t *testing.T) {
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
			kh, keyBytes, err := u.NewAESGCMKey(test.algo)
			if err == nil {
				t.Errorf("NewAESGCMKey(%v) succeeded, want error", test.algo)
			}
			if kh != nil {
				t.Errorf("NewAESGCMKey(%v) returned non-nil keyset handle: %v, want nil", test.algo, kh)
			}
			if keyBytes != nil {
				t.Errorf("NewAESGCMKey(%v) returned non-nil key bytes: %v, want nil", test.algo, keyBytes)
			}
		})
	}
}

func TestEncryptWithAes(t *testing.T) {
	u := &DefaultTPM12Utils{}
	kh, _, err := u.NewAESGCMKey(tpm12.AlgAES256)
	if err != nil {
		t.Fatalf("NewAESGCMKey() failed: %v", err)
	}

	testCases := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{
			name:      "Successful Encryption",
			data:      []byte("This is a secret message."),
			expectErr: false,
		},
		{
			name:      "Empty Data",
			data:      []byte{},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := u.EncryptWithAes(kh, tc.data)

			if tc.expectErr {
				if err == nil {
					t.Errorf("EncryptWithAes(%v) expected an error, got nil", tc.data)
				}
			} else {
				if err != nil {
					t.Errorf("EncryptWithAes(%v) returned an unexpected error: %v", tc.data, err)
				}
				if bytes.Equal(ciphertext, tc.data) && len(tc.data) > 0 {
					t.Errorf("EncryptWithAes(%v) returned ciphertext equal to plaintext, expected different", tc.data)
				}
				// Decrypt to verify
				a, err := aead.New(kh)
				if err != nil {
					t.Fatalf("Failed to create AEAD for decryption: %v", err)
				}
				decrypted, err := a.Decrypt(ciphertext, []byte(""))
				if err != nil {
					t.Errorf("Failed to decrypt ciphertext: %v", err)
				}
				if !bytes.Equal(decrypted, tc.data) {
					t.Errorf("Decrypted data mismatch: got %v, want %v", decrypted, tc.data)
				}
			}
		})
	}
}

func TestEncryptAndDecryptWithSymmetricKey(t *testing.T) {
	u := &DefaultTPM12Utils{}
	ctx := context.Background()
	plaintext := []byte("this is a secret message")

	testCases := []struct {
		name          string
		algo          tpm12.Algorithm
		modifier      func(binaryKeyset []byte, ciphertext []byte) ([]byte, []byte) // Function to modify inputs for failure cases
		expectedError string
	}{
		{
			name: "Success AES256",
			algo: tpm12.AlgAES256,
			modifier: func(binaryKeyset, ciphertext []byte) ([]byte, []byte) {
				return binaryKeyset, ciphertext // No-op
			},
			expectedError: "",
		},
		{
			name: "Success AES128",
			algo: tpm12.AlgAES128,
			modifier: func(binaryKeyset, ciphertext []byte) ([]byte, []byte) {
				return binaryKeyset, ciphertext // No-op
			},
			expectedError: "",
		},
		{
			name: "Failure with wrong key",
			algo: tpm12.AlgAES256,
			modifier: func(binaryKeyset, ciphertext []byte) ([]byte, []byte) {
				// Generate a completely different key to decrypt with.
				_, wrongBinaryKeyset, err := u.NewAESGCMKey(tpm12.AlgAES256)
				if err != nil {
					t.Fatalf("Failed to generate wrong key for test: %v", err)
				}
				return wrongBinaryKeyset, ciphertext
			},
			expectedError: "symmetric key decryption failed",
		},
		{
			name: "Failure with tampered ciphertext",
			algo: tpm12.AlgAES256,
			modifier: func(binaryKeyset, ciphertext []byte) ([]byte, []byte) {
				// Tamper with the ciphertext by flipping a bit
				tamperedCiphertext := make([]byte, len(ciphertext))
				copy(tamperedCiphertext, ciphertext)
				tamperedCiphertext[0] ^= 0xff
				return binaryKeyset, tamperedCiphertext
			},
			expectedError: "symmetric key decryption failed",
		},
		{
			name: "Failure with invalid keyset",
			algo: tpm12.AlgAES256,
			modifier: func(binaryKeyset, ciphertext []byte) ([]byte, []byte) {
				// Provide a corrupted keyset
				return []byte("this is not a valid keyset"), ciphertext
			},
			expectedError: "failed to read keyset from binary",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup: Encrypt the data first
			kh, originalBinaryKeyset, err := u.NewAESGCMKey(tc.algo)
			if err != nil {
				t.Fatalf("NewAESGCMKey failed: %v", err)
			}
			originalCiphertext, err := u.EncryptWithAes(kh, plaintext)
			if err != nil {
				t.Fatalf("EncryptWithAes failed: %v", err)
			}

			// Apply modifications for failure test cases
			modifiedKeyset, modifiedCiphertext := tc.modifier(originalBinaryKeyset, originalCiphertext)

			// The actual test
			decrypted, err := u.DecryptWithSymmetricKey(ctx, modifiedKeyset, modifiedCiphertext, tc.algo, 0)

			assertError(t, err, tc.expectedError, "DecryptWithSymmetricKey")

			// If it was a success case, check the result
			if tc.expectedError == "" {
				if diff := cmp.Diff(plaintext, decrypted); diff != "" {
					t.Errorf("DecryptWithSymmetricKey returned diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}
