package biz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/aes"

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

func TestDecryptWithSymmetricKey(t *testing.T) {
	// Setup a valid encrypted payload for testing decryption.
	plaintext := []byte("a secret message")
	key := make([]byte, 16) // AES-128
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	// Manually perform PKCS#7 padding.
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedPlaintext := append(plaintext, padtext...)

	// Encrypt the padded data using AES-CBC to create a valid test case.
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("failed to generate IV: %v", err)
	}
	ciphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Per the function's contract, the IV is prepended to the ciphertext.
	encryptedDataWithIV := append(iv, ciphertext...)

	tests := []struct {
		name      string
		desc      string
		key       []byte
		data      []byte
		encScheme TPMEncodingScheme
		wantErr   bool
		want      []byte
	}{
		{
			name:      "Success",
			desc:      "Should correctly decrypt a valid AES-CBC payload.",
			key:       key,
			data:      encryptedDataWithIV,
			encScheme: EsSymCBCPKCS5,
			wantErr:   false,
			want:      plaintext,
		},
		{
			name:      "UnsupportedScheme",
			desc:      "Should return an error for an unsupported encryption scheme.",
			key:       key,
			data:      encryptedDataWithIV,
			encScheme: TPMEncodingScheme(0), // An invalid scheme.
			wantErr:   true,
		},
		{
			name:      "CiphertextTooShort",
			desc:      "Should return an error if ciphertext is smaller than the IV.",
			key:       key,
			data:      []byte("short"),
			encScheme: EsSymCBCPKCS5,
			wantErr:   true,
		},
		{
			name: "InvalidPadding",
			desc: "Should return an error for a payload with invalid PKCS#7 padding.",
			key:  key,
			// Manually create a ciphertext with bad padding.
			data:    append(iv, []byte("123456789012345\x07")...),
			encScheme: EsSymCBCPKCS5,
			wantErr:   true,
		},
	}

	u := &DefaultTPM12Utils{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.DecryptWithSymmetricKey(context.Background(), tt.key, tt.data, tpm12.AlgAES128, tt.encScheme)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithSymmetricKey() with desc: %q, error = %v, wantErr %v", tt.desc, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("DecryptWithSymmetricKey() with desc: %q, returned diff (-want +got):\n%s", tt.desc, diff)
				}
			}
		})
	}
}
