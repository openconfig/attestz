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
	"crypto/rsa"
	"encoding/binary"
	"fmt"

	tpm12 "github.com/google/go-tpm/tpm"
)

const (
	_ TPMEncodingScheme = iota // Encryption schemes.
	EsNone
	EsRSAEsPKCSv15
	EsRSAEsOAEPSHA1MGF1
	EsSymCTR
	EsSymOFB
	EsSymCBCPKCS5 = 0xff // esSymCBCPKCS5 was taken from go-tspi

	// Signature schemes. These are only valid under AlgRSA.
	_ TPMSignatureScheme = iota
	SsNone
	SsRSASaPKCS1v15SHA1
	SsRSASaPKCS1v15DER
	SsRSASaPKCS1v15INFO
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

// TPMStorePubkey represents a stored public key - TPM_STORE_PUBKEY from TPM 1.2 specification.
type TPMStorePubkey struct {
	KeyLength uint32 // Length of the public key in bytes.
	Key       []byte // The public key data.
}

// TPMPubKey represents a TPM public key - TPM_PUBKEY from TPM 1.2 specification.
type TPMPubKey struct {
	AlgorithmParms TPMKeyParms    // Parameters defining the key algorithm.
	Pubkey         TPMStorePubkey // The public key itself.
}

// TPMSymmetricKey represents a TPM symmetric key - TPM_SYMMETRIC_KEY from TPM 1.2 specification.
type TPMSymmetricKey struct {
	AlgID     tpm12.Algorithm
	EncScheme TPMEncodingScheme
	Key       []byte
}

// TPMIdentityProof is the structure that contains the identity proof.
// TPM_IDENTITY_PROOF from TPM 1.2 specification.
type TPMIdentityProof struct {
	TPMStructVer           uint32    // Version of the TPM structure.
	AttestationIdentityKey TPMPubKey // Attestation Identity Key (AIK) public key - TPM_PUBKEY.
	LabelArea              []byte    // Text label for the new identity.
	IdentityBinding        []byte    // Signature value of identity binding.
	EndorsementCredential  []byte    // TPM endorsement credential.
	PlatformCredential     []byte    // TPM platform credential.
	ConformanceCredential  []byte    // TPM conformance credential.
}

// TPMIdentityContents is the structure that contains the identity contents.
// TPM_IDENTITY_CONTENTS from TPM 1.2 specification.
type TPMIdentityContents struct {
	TPMStructVer      uint32    // Version of the TPM structure.
	Ordinal           uint32    // Ordinal of the structure.
	LabelPrivCADigest []byte    // Hash of the label private CA.
	IdentityPubKey    TPMPubKey // Identity Key (AIK) public key - TPM_PUBKEY.
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
	algorithmID, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithmID: %w", err)
	}
	result.AlgID = tpm12.Algorithm(algorithmID)

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
func (u *DefaultTPM12Utils) ParseSymmetricKey(_ []byte) (*TPMSymmetricKey, error) {
	// TODO: Implement the parsing of TPMSymmetricKey.
	// For now, we just return empty data.
	return &TPMSymmetricKey{}, nil
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
	// TODO: Implement the decryption using a private key.
	// For now, we just return the data as is.
	return data, nil
}

// EncryptWithAes encrypts data using an AES key.
func (u *DefaultTPM12Utils) EncryptWithAes(_ []byte, data []byte) ([]byte, error) {
	// TODO: Implement the encryption using AES-GCM.
	// For now, we just return the data as is.
	return data, nil
}

// DecryptWithSymmetricKey decrypts data using a private key.
func (u *DefaultTPM12Utils) DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	// TODO: Implement the decryption using a symmetric key.
	// For now, we just return the data as is.
	return data, nil
}

// VerifySignature verifies a signature using a public key.
func (u *DefaultTPM12Utils) VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error) {
	// TODO: Implement the signature verification using a public key.
	// For now, we just return true.
	return true, nil
}
