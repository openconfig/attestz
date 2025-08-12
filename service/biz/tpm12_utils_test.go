package biz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"

	// #nosec
	"crypto/sha1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	tpm12 "github.com/google/go-tpm/tpm"
)

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
		TPMStructVer:      0x01010000,
		Ordinal:           0x00000079,
		LabelPrivCADigest: sampleDigest,
		IdentityPubKey:    *samplePubKey,
	}

	// Manually construct the expected byte slice
	var expectedBuf bytes.Buffer
	binaryWriteUint32(&expectedBuf, identityContents.TPMStructVer)
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
