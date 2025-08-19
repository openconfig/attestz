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

package biz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/aes" 
	"crypto/rsa"
	"crypto/cipher"
	"math"

	// #nosec
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	tpm12 "github.com/google/go-tpm/tpm"
)

const (
	// Encryption schemes based on TPM 1.2 Spec.
	EsNone              TPMEncodingScheme = 0x0001
	EsRSAEsPKCSv15      TPMEncodingScheme = 0x0002
	EsRSAEsOAEPSHA1MGF1 TPMEncodingScheme = 0x0003
	EsSymCTR            TPMEncodingScheme = 0x0004
	EsSymOFB            TPMEncodingScheme = 0x0005
	EsSymCBCPKCS5       TPMEncodingScheme = 0xff // EsSymCBCPKCS5 was taken from go-tspi

	// Signature schemes based on TPM 1.2 Spec. These are only valid under AlgRSA.
	SsNone              TPMSignatureScheme = 0x0001
	SsRSASaPKCS1v15SHA1 TPMSignatureScheme = 0x0002
	SsRSASaPKCS1v15DER  TPMSignatureScheme = 0x0003
	SsRSASaPKCS1v15INFO TPMSignatureScheme = 0x0004
)

// Note: All the uint values in TPM_* structures in this file use big endian (network byte order).

// TPMEncodingScheme represents the encoding scheme used in TPM structures.
type TPMEncodingScheme uint16

// TPMSignatureScheme represents the signature scheme used in TPM structures.
type TPMSignatureScheme uint16

// TPMParams represents the parameters for TPMKeyParms, it can be either RSA or Symmetric parameters.
type TPMParams struct {
	RSAParams *TPMRSAKeyParms
	SymParams *TPMSymmetricKeyParms
}

// TPMKeyParms is the structure that contains the key parameters - TPM_KEY_PARMS from TPM 1.2 specification.
type TPMKeyParms struct {
	AlgID     tpm12.Algorithm    // Algorithm identifier.
	EncScheme TPMEncodingScheme  // Encryption scheme identifier.
	SigScheme TPMSignatureScheme // Signature scheme identifier.
	Params    TPMParams          // Parameters defining the key algorithm.
}

// TPMSymmetricKeyParms is the structure that contains the sym key parameters - TPM_SYMMETRIC_KEY_PARMS from TPM 1.2 specification.
type TPMSymmetricKeyParms struct {
	KeyLength uint32
	BlockSize uint32
	IV        []byte
}

// TPMRSAKeyParms is the structure that contains the RSA key parameters - TPM_RSA_KEY_PARMS from TPM 1.2 specification.
type TPMRSAKeyParms struct {
	KeyLength uint32
	NumPrimes uint32
	Exponent  []byte
}

// TPMStorePubKey represents a stored public key - TPM_STORE_PUBKEY from TPM 1.2 specification.
type TPMStorePubKey struct {
	KeyLength uint32 // Length of the public key in bytes.
	Key       []byte // The public key data.
}

// TPMPubKey represents a TPM public key - TPM_PUBKEY from TPM 1.2 specification.
type TPMPubKey struct {
	AlgorithmParms TPMKeyParms    // Parameters defining the key algorithm.
	PubKey         TPMStorePubKey // The public key itself.
}

// TPMSymmetricKey represents a TPM symmetric key - TPM_SYMMETRIC_KEY from TPM 1.2 specification.
type TPMSymmetricKey struct {
	AlgID     tpm12.Algorithm
	EncScheme TPMEncodingScheme
	Key       []byte
}

// TPMStructVer represents the TPM_STRUCT_VER from TPM 1.2 specification.
type TPMStructVer struct {
	Major    uint8 // MUST be 0x01
	Minor    uint8 // MUST be 0x01
	RevMajor uint8 // MUST be 0x00
	RevMinor uint8 // MUST be 0x00
}

// GetDefaultTPMStructVer returns the default value for TPMStructVer as per TCG Spec.
func GetDefaultTPMStructVer() TPMStructVer {
	return TPMStructVer{
		Major:    0x01,
		Minor:    0x01,
		RevMajor: 0x00,
		RevMinor: 0x00,
	}
}

// TPMIdentityProof is the structure that contains the identity proof.
// TPM_IDENTITY_PROOF from TPM 1.2 specification.
type TPMIdentityProof struct {
	TPMStructVer           TPMStructVer // Version of the TPM structure.
	AttestationIdentityKey TPMPubKey    // Attestation Identity Key (AIK) public key - TPM_PUBKEY.
	LabelArea              []byte       // Text label for the new identity.
	IdentityBinding        []byte       // Signature value of identity binding.
	EndorsementCredential  []byte       // TPM endorsement credential.
	PlatformCredential     []byte       // TPM platform credential.
	ConformanceCredential  []byte       // TPM conformance credential.
}

// TPMIdentityContents is the structure that contains the identity contents.
// TPM_IDENTITY_CONTENTS from TPM 1.2 specification.
type TPMIdentityContents struct {
	TPMStructVer      TPMStructVer // Version of the TPM structure.
	Ordinal           uint32       // Ordinal of the structure.
	LabelPrivCADigest []byte       // Hash of the label private CA.
	IdentityPubKey    TPMPubKey    // Identity Key (AIK) public key - TPM_PUBKEY.
}

// TPMIdentityReq is a response from the TPM containing the identity proof and binding.
// TPM_IDENTITY_REQ from TPM 1.2 specification.
type TPMIdentityReq struct {
	AsymAlgorithm TPMKeyParms
	SymAlgorithm  TPMKeyParms
	AsymBlob      []byte
	SymBlob       []byte
}

// TPM12Utils is an interface for TPM 1.2 utility functions.
// This interface was created to allow for mocking of the TPM 1.2 utility functions in unit tests
// since it is not possible to test the Rotate AIK flow with stubbed data.
type TPM12Utils interface {
	ParseSymmetricKeyParms(keyParms []byte) (*TPMSymmetricKeyParms, error)
	ParseRSAKeyParms(keyParms []byte) (*TPMRSAKeyParms, error)
	ParseKeyParmsFromReader(reader *bytes.Reader) (*TPMKeyParms, error)
	ParseIdentityRequest(data []byte) (*TPMIdentityReq, error)
	ParseSymmetricKey(data []byte) (*TPMSymmetricKey, error)
	ParseIdentityProof(data []byte) (*TPMIdentityProof, error)
	EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error)
	DecryptWithPrivateKey(ctx context.Context, privateKey *rsa.PrivateKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error)
	EncryptWithAes(key []byte, data []byte) ([]byte, error)
	DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error)
	VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error)
	SerializeStorePubKey(pubKey *TPMStorePubKey) ([]byte, error)
	SerializeRSAKeyParms(rsaParms *TPMRSAKeyParms) ([]byte, error)
	SerializeSymmetricKeyParms(symParms *TPMSymmetricKeyParms) ([]byte, error)
	SerializeKeyParms(keyParms *TPMKeyParms) ([]byte, error)
	SerializePubKey(pubKey *TPMPubKey) ([]byte, error)
	SerializeIdentityContents(identityContents *TPMIdentityContents) ([]byte, error)
	ConstructPubKey(publicKey *rsa.PublicKey) (*TPMPubKey, error)
	ConstructIdentityContents(publicKey *rsa.PublicKey) (*TPMIdentityContents, error)
}

// DefaultTPM12Utils is a concrete implementation of the TPM12Utils interface.
type DefaultTPM12Utils struct{}

// ParseSymmetricKeyParms from bytes to TPMSymmetricKeyParms.
func (u *DefaultTPM12Utils) ParseSymmetricKeyParms(keyParms []byte) (*TPMSymmetricKeyParms, error) {
	reader := bytes.NewReader(keyParms)
	result := &TPMSymmetricKeyParms{}

	// Read keyLength (4 bytes).
	keyLength, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyLength: %w", err)
	}
	result.KeyLength = keyLength

	// Read blockSize (4 bytes).
	blockSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read blockSize: %w", err)
	}
	result.BlockSize = blockSize

	// Read ivSize (4 bytes).
	ivSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read ivSize: %w", err)
	}

	// Read IV (ivSize bytes).
	iv, err := readBytes(reader, ivSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read IV (size %d): %w", ivSize, err)
	}
	result.IV = iv

	// Check for leftover bytes.
	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TPM_SYMMETRIC_KEY_PARMS block after parsing: %d", reader.Len())
	}

	return result, nil
}

// ParseRSAKeyParms from bytes to TPMRSAKeyParms.
func (u *DefaultTPM12Utils) ParseRSAKeyParms(keyParms []byte) (*TPMRSAKeyParms, error) {
	reader := bytes.NewReader(keyParms)
	result := &TPMRSAKeyParms{}

	// Read keyLength (4 bytes).
	keyLength, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyLength: %w", err)
	}
	result.KeyLength = keyLength

	// Read numPrimes (4 bytes).
	numPrimes, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read numPrimes: %w", err)
	}
	result.NumPrimes = numPrimes

	// Read exponentSize (4 bytes).
	exponentSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exponentSize: %w", err)
	}

	// Read exponent.
	exponent, err := readBytes(reader, exponentSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read exponent: %w", err)
	}
	result.Exponent = exponent

	// Check for leftover bytes.
	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TPM_RSA_KEY_PARMS block after parsing: %d", reader.Len())
	}

	return result, nil
}

// readUint16 is a helper function to read a 2-byte Big Endian unsigned integer.
func readUint16(r *bytes.Reader) (uint16, error) {
	var result uint16
	err := binary.Read(r, binary.BigEndian, &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

// ParseKeyParmsFromReader parses a TPM_KEY_PARMS structure from a bytes.Reader.
func (u *DefaultTPM12Utils) ParseKeyParmsFromReader(reader *bytes.Reader) (*TPMKeyParms, error) {
	result := &TPMKeyParms{}

	// Read algorithmID (4 bytes).
	algorithmID, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithmID: %w", err)
	}
	result.AlgID = tpm12.Algorithm(algorithmID)
	if _, ok := tpm12.AlgMap[result.AlgID]; !ok {
		return nil, fmt.Errorf("invalid algorithmID: %v", result.AlgID)
	}

	// Read encScheme (2 bytes).
	encScheme, err := readUint16(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encScheme: %w", err)
	}
	result.EncScheme = TPMEncodingScheme(encScheme)

	// Read sigScheme (2 bytes).
	sigScheme, err := readUint16(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read sigScheme: %w", err)
	}
	result.SigScheme = TPMSignatureScheme(sigScheme)

	// Read paramSize (4 bytes).
	paramSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read paramSize: %w", err)
	}

	// Read parms (paramSize bytes).
	parms, err := readBytes(reader, paramSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read parms (size %d): %w", paramSize, err)
	}

	// Parse parms based on algorithmID.
	switch result.AlgID {
	case tpm12.AlgRSA:
		rsaParms, err := u.ParseRSAKeyParms(parms)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key parms: %w", err)
		}
		result.Params.RSAParams = rsaParms
	case tpm12.AlgAES128, tpm12.AlgAES192, tpm12.AlgAES256:
		symParms, err := u.ParseSymmetricKeyParms(parms)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Symmetric key parms: %w", err)
		}
		result.Params.SymParams = symParms
	default:
		// Other algorithms like SHA, HMAC, MGF1 have no params.
		if paramSize > 0 {
			return nil, fmt.Errorf("unexpected params size for algorithm %v: %d", result.AlgID, paramSize)
		}
	}

	// Note: We don't check for leftover bytes here because the Key params size can be variable
	// so the reader is passed in, not a set amount of bytes.

	return result, nil
}

// ParseIdentityRequest from bytes to TPMIdentityReq.
func (u *DefaultTPM12Utils) ParseIdentityRequest(data []byte) (*TPMIdentityReq, error) {
	reader := bytes.NewReader(data)
	result := &TPMIdentityReq{}

	// read asymBlobSize (UINT32).
	asymBlobSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read asymBlobSize: %w", err)
	}

	// read symBlobSize (UINT32).
	symBlobSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read symBlobSize: %w", err)
	}

	// Read asymAlgorithm (TPM_KEY_PARMS).
	asymAlgorithm, err := u.ParseKeyParmsFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse asymAlgorithm (TPM_KEY_PARMS): %w", err)
	}
	result.AsymAlgorithm = *asymAlgorithm

	// Read symAlgorithm (TPM_KEY_PARMS).
	symAlgorithm, err := u.ParseKeyParmsFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse symAlgorithm (TPM_KEY_PARMS): %w", err)
	}
	result.SymAlgorithm = *symAlgorithm

	// Read asymBlob (asymBlobSize bytes).
	asymBlob, err := readBytes(reader, asymBlobSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read asymBlob: %w", err)
	}
	result.AsymBlob = asymBlob

	// Read symBlob (symBlobSize bytes).
	symBlob, err := readBytes(reader, symBlobSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read symBlob: %w", err)
	}
	result.SymBlob = symBlob

	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TPM_IDENTITY_REQ after parsing: %d", reader.Len())
	}

	return result, nil
}

// ParseSymmetricKey from bytes to TPMSymmetricKey.
func (u *DefaultTPM12Utils) ParseSymmetricKey(keyBytes []byte) (*TPMSymmetricKey, error) {
	reader := bytes.NewReader(keyBytes)
	result := &TPMSymmetricKey{}

	// Read algorithmID (4 bytes).
	algorithmID, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithmID: %w", err)
	}
	result.AlgID = tpm12.Algorithm(algorithmID)
	if _, ok := tpm12.AlgMap[result.AlgID]; !ok {
		return nil, fmt.Errorf("invalid algorithmID: %v", result.AlgID)
	}

	// Read encScheme (2 bytes).
	encScheme, err := readUint16(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encScheme: %w", err)
	}
	result.EncScheme = TPMEncodingScheme(encScheme)

	// Read keySize (2 bytes).
	keySize, err := readUint16(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keySize: %w", err)
	}
	if keySize == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read key.
	key, err := readBytes(reader, uint32(keySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read key (size %d): %w", keySize, err)
	}
	result.Key = key

	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TPMSymmetricKey block after parsing: %d", reader.Len())
	}

	return result, nil
}

// ParseIdentityProof from bytes to TPMIdentityProof.
func (u *DefaultTPM12Utils) ParseIdentityProof(_ []byte) (*TPMIdentityProof, error) {
	// TODO: Implement the parsing of the identity proof.
	// For now, we just return empty data.
	return &TPMIdentityProof{}, nil
}

// EncryptWithPublicKey encrypts data using a public key.
func (u *DefaultTPM12Utils) EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	// TODO: Implement the encryption using a public key.
	// For now, we just return the data as is.
	return data, nil
}

// DecryptWithPrivateKey decrypts data using a private key.
func (u *DefaultTPM12Utils) DecryptWithPrivateKey(ctx context.Context, privateKey *rsa.PrivateKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if algo != tpm12.AlgRSA {
		return nil, fmt.Errorf("unsupported algorithm: %v", algo)
	}
	switch encScheme {
	case EsRSAEsOAEPSHA1MGF1:
		// #nosec
		return rsa.DecryptOAEP(sha1.New(), nil, privateKey, data, []byte{}) /* #nosec G505 */
	case EsRSAEsPKCSv15:
		return rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	default:
		return nil, fmt.Errorf("unsupported encoding scheme: %v", encScheme)
	}
}

// EncryptWithAes encrypts data using an AES key.
func (u *DefaultTPM12Utils) EncryptWithAes(_ []byte, data []byte) ([]byte, error) {
	// TODO: Implement the encryption using AES-GCM.
	// For now, we just return the data as is.
	return data, nil
}

// DecryptWithSymmetricKey decrypts data using a private key.
func (u *DefaultTPM12Utils) DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if encScheme != EsSymCBCPKCS5 {
		return nil, fmt.Errorf("unsupported symmetric encryption scheme: %v", encScheme)
	}

	// Create a new AES cipher block from the symmetric key.
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// The IV is prepended to the ciphertext. For AES, the IV size is
	// the same as the block size.
	ivSize := block.BlockSize()
	if len(data) < ivSize {
		return nil, fmt.Errorf("ciphertext is shorter than IV size of %d bytes", ivSize)
	}

	// Extract the IV from the beginning of the data.
	iv := data[:ivSize]
	// The rest of the data is the actual ciphertext.
	ciphertext := data[ivSize:]

	// The ciphertext must be a multiple of the block size.
	if len(ciphertext)%ivSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Create a new CBC decrypter.
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the data. The decrypted plaintext will be stored in the same
	// underlying array as the ciphertext.
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted plaintext using PKCS#5/PKCS#7.
	plaintext := ciphertext
	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) || padding == 0 {
		return nil, fmt.Errorf("invalid PKCS#5 padding value: %d", padding)
	}
	// Verify that all padding bytes are correct.
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if int(plaintext[i]) != padding {
			return nil, fmt.Errorf("invalid PKCS#5 padding found")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

// VerifySignature verifies a signature using a public key.
func (u *DefaultTPM12Utils) VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error) {
	// TODO: Implement the signature verification using a public key.
	// For now, we just return true.
	return true, nil
}

// SerializeStorePubKey serializes a TPMStorePubKey to bytes.
func (u *DefaultTPM12Utils) SerializeStorePubKey(pubKey *TPMStorePubKey) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, pubKey.KeyLength); err != nil {
		return nil, fmt.Errorf("failed to write the pubKey length to the buffer: %w", err)
	}

	buf.Write(pubKey.Key)

	return buf.Bytes(), nil
}

// SerializeRSAKeyParms serializes a TPMRSAKeyParms to bytes.
func (u *DefaultTPM12Utils) SerializeRSAKeyParms(rsaParms *TPMRSAKeyParms) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, rsaParms.KeyLength); err != nil {
		return nil, fmt.Errorf("failed to write the key length to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, rsaParms.NumPrimes); err != nil {
		return nil, fmt.Errorf("failed to write the number of primes to the buffer: %w", err)
	}
	expLen := len(rsaParms.Exponent)
	if expLen > math.MaxUint32 {
		return nil, fmt.Errorf("rsa.Parms.exponent length (%d) exceeds maximum uint32 size", expLen)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(expLen)); err != nil {
		return nil, fmt.Errorf("failed to write the exponent length to the buffer: %w", err)
	}

	buf.Write(rsaParms.Exponent)

	return buf.Bytes(), nil
}

// SerializeSymmetricKeyParms serializes a TPMSymmetricKeyParms to bytes.
func (u *DefaultTPM12Utils) SerializeSymmetricKeyParms(symParms *TPMSymmetricKeyParms) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, symParms.KeyLength); err != nil {
		return nil, fmt.Errorf("failed to write the key length to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, symParms.BlockSize); err != nil {
		return nil, fmt.Errorf("failed to write the block size to the buffer: %w", err)
	}
	ivLen := len(symParms.IV)
	if ivLen > math.MaxUint32 {
		return nil, fmt.Errorf("symParms.IV length (%d) exceeds maximum uint32 size", ivLen)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(ivLen)); err != nil {
		return nil, fmt.Errorf("failed to write the IV length to the buffer: %w", err)
	}

	buf.Write(symParms.IV)

	return buf.Bytes(), nil
}

// SerializeKeyParms serializes a TPMKeyParms to bytes.
func (u *DefaultTPM12Utils) SerializeKeyParms(keyParms *TPMKeyParms) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(keyParms.AlgID)); err != nil {
		return nil, fmt.Errorf("failed to write the algorithm ID to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(keyParms.EncScheme)); err != nil {
		return nil, fmt.Errorf("failed to write the encoding scheme to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(keyParms.SigScheme)); err != nil {
		return nil, fmt.Errorf("failed to write the signing scheme to the buffer: %w", err)
	}

	var paramBytes []byte
	var err error
	switch keyParms.AlgID {
	case tpm12.AlgRSA:
		if keyParms.Params.RSAParams != nil {
			paramBytes, err = u.SerializeRSAKeyParms(keyParms.Params.RSAParams)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize RSA key params: %w", err)
			}
		}
	case tpm12.AlgAES128, tpm12.AlgAES192, tpm12.AlgAES256:
		if keyParms.Params.SymParams != nil {
			paramBytes, err = u.SerializeSymmetricKeyParms(keyParms.Params.SymParams)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize symmetric key params: %w", err)
			}
		}
	default:
		// Other algorithms like SHA, HMAC, MGF1 have no params.
		if keyParms.Params.RSAParams != nil || keyParms.Params.SymParams != nil {
			return nil, fmt.Errorf("unexpected params for algorithm %v: %+v", keyParms.AlgID, keyParms.Params)
		}
	}

	paramLen := len(paramBytes)
	if paramLen > math.MaxUint32 {
		return nil, fmt.Errorf("params length (%d) exceeds maximum uint32 size", paramLen)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(paramLen)); err != nil {
		return nil, fmt.Errorf("failed to write the params length to the buffer: %w", err)
	}

	buf.Write(paramBytes)

	return buf.Bytes(), nil
}

// SerializePubKey serializes a TPMPubKey to bytes.
func (u *DefaultTPM12Utils) SerializePubKey(pubKey *TPMPubKey) ([]byte, error) {
	var buf bytes.Buffer
	keyParmsBytes, err := u.SerializeKeyParms(&pubKey.AlgorithmParms)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize AlgorithmParms: %w", err)
	}

	buf.Write(keyParmsBytes)

	pubKeyBytes, err := u.SerializeStorePubKey(&pubKey.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PubKey: %w", err)
	}

	buf.Write(pubKeyBytes)

	return buf.Bytes(), nil
}

// SerializeIdentityContents serializes a TPMIdentityContents to bytes.
func (u *DefaultTPM12Utils) SerializeIdentityContents(identityContents *TPMIdentityContents) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, identityContents.TPMStructVer); err != nil {
		return nil, fmt.Errorf("failed to write the struct version to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, identityContents.Ordinal); err != nil {
		return nil, fmt.Errorf("failed to write the ordinal to the buffer: %w", err)
	}

	buf.Write(identityContents.LabelPrivCADigest)

	identityPubKeyBytes, err := u.SerializePubKey(&identityContents.IdentityPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize IdentityPubKey: %w", err)
	}

	buf.Write(identityPubKeyBytes)

	return buf.Bytes(), nil
}

// ConstructPubKey creates a TPMPubKey from an rsa.PublicKey.
func (u *DefaultTPM12Utils) ConstructPubKey(publicKey *rsa.PublicKey) (*TPMPubKey, error) {
	if publicKey == nil || publicKey.N == nil {
		return nil, fmt.Errorf("publicKey or its modulus cannot be nil")
	}

	e := publicKey.E
	if e > math.MaxUint32 {
		return nil, fmt.Errorf("exponent (%d) exceeds maximum uint32 size", e)
	}
	exponent := uint32(e) // #nosec G115 -- e is checked against math.MaxUint32
	if exponent == 0 {
		exponent = 65537 // Default RSA exponent
	}

	b := publicKey.N.BitLen()
	if b > math.MaxUint32 {
		return nil, fmt.Errorf("publicKey bit length (%d) exceeds maximum uint32 size", b)
	}
	bitLen := uint32(b) // #nosec G115 -- b is checked against math.MaxUint32

	keyBytes := publicKey.N.Bytes()
	b = len(keyBytes)
	if b > math.MaxUint32 {
		return nil, fmt.Errorf("publicKey byte length (%d) exceeds maximum uint32 size", b)
	}
	byteLen := uint32(b) // #nosec G115 -- b is checked against math.MaxUint32

	return &TPMPubKey{
		AlgorithmParms: TPMKeyParms{
			AlgID:     tpm12.AlgRSA,
			EncScheme: EsRSAEsOAEPSHA1MGF1,
			SigScheme: SsRSASaPKCS1v15SHA1,
			Params: TPMParams{
				RSAParams: &TPMRSAKeyParms{
					KeyLength: bitLen,
					NumPrimes: 2,
					Exponent:  binary.BigEndian.AppendUint32([]byte{}, exponent),
				},
			},
		},
		PubKey: TPMStorePubKey{
			KeyLength: byteLen,
			Key:       keyBytes,
		},
	}, nil
}

// ConstructIdentityContents constructs the TPM_IDENTITY_CONTENTS structure.
func (u *DefaultTPM12Utils) ConstructIdentityContents(publicKey *rsa.PublicKey) (*TPMIdentityContents, error) {
	tpmPubKey, err := u.ConstructPubKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to construct TPMPubKey: %w", err)
	}

	privacyCABytes, err := u.SerializePubKey(tpmPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize privacyCA: %w", err)
	}

	identityLabel := []byte("Identity")

	hashInput := append(identityLabel, privacyCABytes...)

	// #nosec
	hasher := sha1.New()
	if _, err := hasher.Write(hashInput); err != nil {
		return nil, fmt.Errorf("failed to write to hasher: %w", err)
	}
	labelPrivCADigest := hasher.Sum(nil)

	return &TPMIdentityContents{
		TPMStructVer:      GetDefaultTPMStructVer(),
		Ordinal:           0x00000079,
		LabelPrivCADigest: labelPrivCADigest,
		IdentityPubKey:    *tpmPubKey,
	}, nil
}
