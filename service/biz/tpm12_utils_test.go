package biz


import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	// #nosec
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	tpm12 "github.com/google/go-tpm/tpm"
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

// identityProofBytes provides options for creating TPMIdentityProof bytes for testing.
// Fields left nil will use default values within the build function.
type identityProofBytes struct {
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

func buildIdentityProofBytes(t *testing.T, opts identityProofBytes) []byte {
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
		options  identityProofBytes
		expected *TPMIdentityProof
	}{
		{
			name:    "Valid Identity Proof",
			options: identityProofBytes{}, // Use all defaults
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
			input:         buildIdentityProofBytes(t, identityProofBytes{})[:3],
			expectedError: "failed to read TPMStructVer",
		},
		{
			// Input is long enough for TPMStructVer, but too short for the LabelArea size field.
			name:          "Input too short for LabelArea size",
			input:         buildIdentityProofBytes(t, identityProofBytes{})[:4],
			expectedError: "failed to read LabelArea size",
		},
		{
			// Input is long enough for LabelArea size, but too short for the IdentityBinding size field.
			name:          "Input too short for IdentityBinding size",
			input:         buildIdentityProofBytes(t, identityProofBytes{})[:8],
			expectedError: "failed to read IdentityBinding size",
		},
		{
			// Input is truncated within the AttestationIdentityKey field.
			name:          "Input too short for AIK",
			input:         buildIdentityProofBytes(t, identityProofBytes{})[:24],
			expectedError: "failed to parse AttestationIdentityKey",
		},
		{
			name: "LabelAreaSize too large",
			input: buildIdentityProofBytes(t, identityProofBytes{
				LabelAreaSize: ptrUint32(100), // Larger than available bytes
			}),
			expectedError: "failed to read LabelArea",
		},
		{
			name: "IdentityBindingSize too large",
			input: buildIdentityProofBytes(t, identityProofBytes{
				IdentityBindingSize: ptrUint32(100),
			}),
			expectedError: "failed to read IdentityBinding",
		},
		{
			name: "EndorsementCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProofBytes{
				EndorsementCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read EndorsementCredential",
		},
		{
			name: "PlatformCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProofBytes{
				PlatformCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read PlatformCredential",
		},
		{
			name: "ConformanceCredentialSize too large",
			input: buildIdentityProofBytes(t, identityProofBytes{
				ConformanceCredentialSize: ptrUint32(100),
			}),
			expectedError: "failed to read ConformanceCredential",
		},
		{
			// Input has extra bytes appended after a valid TPMIdentityProof structure.
			name:          "Leftover bytes",
			input:         append(buildIdentityProofBytes(t, identityProofBytes{}), 0xDE, 0xAD),
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
				t.Errorf("NewAESCBCKey(%v) returned AlgID %v, want %v", test.algo, symKey.AlgID, test.algo)
			}
			if symKey.EncScheme != EsSymCBCPKCS5 {
				t.Errorf("NewAESCBCKey(%v) returned EncScheme %v, want %v", test.algo, symKey.EncScheme, EsSymCBCPKCS5)
			}
			if len(symKey.Key) != test.expectedLen {
				t.Errorf("NewAESCBCKey(%v) returned key of length %d, want %d", test.algo, len(symKey.Key), test.expectedLen)
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

			block, err := aes.NewCipher(symKey.Key)
			if err != nil {
				t.Fatalf("Failed to create AES cipher for decryption: %v", err)
			}

			if len(encrypted)%blockSize != 0 {
				t.Fatalf("Ciphertext is not a multiple of the block size")
			}

			decrypted := make([]byte, len(encrypted))
			mode := cipher.NewCBCDecrypter(block, iv)
			mode.CryptBlocks(decrypted, encrypted)

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
			expectedError: "unsupported algorithm for EncryptWithSymmetricKey",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := u.EncryptWithAES(tc.symKey, tc.data)
			assertError(t, err, tc.expectedError, "EncryptWithAES")
		})
	}
}



// Helper function to encrypt with AES-CBC for testing purposes.
// This function prepends the IV to the ciphertext.
func encryptWithAESCBC(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// PKCS#7 Padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintext = append(plaintext, padtext...)

	if len(plaintext)%aes.BlockSize != 0 {
		t.Fatalf("Plaintext is not a multiple of the block size after padding")
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	// Use crypto/rand.Read directly to fill the IV
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}



func TestDecryptWithSymmetricKey(t *testing.T) {
	u := &DefaultTPM12Utils{}
	ctx := context.Background()
	plaintext := []byte("This is a secret message.")

	// Key sizes to test
	key16 := []byte("0123456789abcdef")                 // AES-128
	key24 := []byte("0123456789abcdef01234567")         // AES-192
	key32 := []byte("0123456789abcdef0123456789abcdef") // AES-256

	// Success test cases
	successTestCases := []struct {
		name string
		key  []byte
		algo tpm12.Algorithm
	}{
		{"Success AES128", key16, tpm12.AlgAES128},
		{"Success AES192", key24, tpm12.AlgAES192},
		{"Success AES256", key32, tpm12.AlgAES256},
	}

	for _, tc := range successTestCases {
		t.Run(tc.name, func(t *testing.T) {
			validCiphertext := encryptWithAESCBC(t, tc.key, plaintext)
			decrypted, err := u.DecryptWithSymmetricKey(ctx, tc.key, validCiphertext, tc.algo, EsSymCBCPKCS5)
			assertError(t, err, "", "DecryptWithSymmetricKey Success")
			if diff := cmp.Diff(plaintext, decrypted); diff != "" {
				t.Errorf("DecryptWithSymmetricKey returned diff (-want +got):\n%s", diff)
			}
		})
	}

	// Failure test cases
	validCiphertext32 := encryptWithAESCBC(t, key32, plaintext)
	tamperedInvalidPaddingValue := make([]byte, len(validCiphertext32))
	copy(tamperedInvalidPaddingValue, validCiphertext32)
	tamperedInvalidPaddingValue[len(tamperedInvalidPaddingValue)-1] = byte(aes.BlockSize + 1)

	failureTestCases := []struct {
		name          string
		key           []byte
		data          []byte
		encScheme     TPMEncodingScheme
		expectedError string
	}{
		{"Failure Unsupported Scheme", key32, validCiphertext32, EsNone, "unsupported symmetric encryption scheme"},
		{"Failure Short Ciphertext", key32, []byte("short"), EsSymCBCPKCS5, "ciphertext is shorter than IV size"},
		{"Failure Not Multiple of Block Size", key32, validCiphertext32[:len(validCiphertext32)-1], EsSymCBCPKCS5, "ciphertext is not a multiple of the block size"},
		{"Failure Invalid Padding Value", key32, tamperedInvalidPaddingValue, EsSymCBCPKCS5, "invalid PKCS#7 padding value"},
		{"Failure Wrong Key Size", []byte("wrong size"), validCiphertext32, EsSymCBCPKCS5, "failed to create AES cipher: crypto/aes: invalid key size"},
		{"Failure Different Key Same Size", []byte("a-different-32-byte-secret-key!!"), validCiphertext32, EsSymCBCPKCS5, "invalid PKCS#7 padding"},
	}

	for _, tc := range failureTestCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := u.DecryptWithSymmetricKey(ctx, tc.key, tc.data, tpm12.AlgAES256, tc.encScheme)
			assertError(t, err, tc.expectedError, "DecryptWithSymmetricKey Failure")
		})
	}
}
