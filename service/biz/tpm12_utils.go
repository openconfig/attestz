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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"
	"math/big"
	"slices"

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

	// tpmLabel is the label used in OAEP encryption and is "TCPA" encoded in UTF-16BE.
	tpmLabel = "TCPA"
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
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf#page=35
type TPMStructVer struct {
	Major    uint8 // MUST be 0x01
	Minor    uint8 // MUST be 0x01
	RevMajor uint8 // MUST be 0x00
	RevMinor uint8 // MUST be 0x00
}

var (
	ErrUnsupportedScheme = errors.New("unsupported symmetric encryption scheme")
	ErrInvalidPadding    = errors.New("invalid PKCS#5 padding")
)

// GetDefaultTPMStructVer returns the default value for TPMStructVer as per TCG Spec.
func GetDefaultTPMStructVer() TPMStructVer {
	return TPMStructVer{
		Major:    0x01,
		Minor:    0x01,
		RevMajor: 0x00,
		RevMinor: 0x00,
	}
}

// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf#page=119
// ParseTpmStructVer parses the TPM_STRUCT_VER from a reader and validates it.
func (u *DefaultTPM12Utils) ParseTpmStructVer(reader *bytes.Reader) (*TPMStructVer, error) {
	var tpmStructVer TPMStructVer
	if err := binary.Read(reader, binary.BigEndian, &tpmStructVer); err != nil {
		return nil, fmt.Errorf("failed to read TPMStructVer: %w", err)
	}
	if tpmStructVer.Major != 1 || tpmStructVer.Minor != 1 || tpmStructVer.RevMajor != 0 || tpmStructVer.RevMinor != 0 {
		return nil, fmt.Errorf("invalid TPM_STRUCT_VER: got %d.%d.%d.%d, want 1.1.0.0", tpmStructVer.Major, tpmStructVer.Minor, tpmStructVer.RevMajor, tpmStructVer.RevMinor)
	}
	return &tpmStructVer, nil
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

// TPMAsymCAContents is the structure that contains the asymmetric CA contents.
// TPM_ASYM_CA_CONTENTS from TPM 1.2 specification.
type TPMAsymCAContents struct {
	SessionKey TPMSymmetricKey // The session key.
	IDDigest   [20]byte        // The digest of the identity key (TPM_PUBKEY)
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
	NewAESCBCKey(algo tpm12.Algorithm) (*TPMSymmetricKey, error)
	EncryptWithAES(symKey *TPMSymmetricKey, data []byte) ([]byte, *TPMKeyParms, error)
	DecryptWithSymmetricKey(ctx context.Context, symKey *TPMSymmetricKey, keyParams *TPMKeyParms, ciphertext []byte) ([]byte, error)
	TpmPubKeyToRSAPubKey(pubKey *TPMPubKey) (*rsa.PublicKey, error)
	VerifySignatureWithRSAKey(ctx context.Context, pubKey *TPMPubKey, signature []byte, digest []byte) (bool, error)
	VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error)
	SerializeStorePubKey(pubKey *TPMStorePubKey) ([]byte, error)
	SerializeRSAKeyParms(rsaParms *TPMRSAKeyParms) ([]byte, error)
	SerializeSymmetricKeyParms(symParms *TPMSymmetricKeyParms) ([]byte, error)
	SerializeKeyParms(keyParms *TPMKeyParms) ([]byte, error)
	SerializePubKey(pubKey *TPMPubKey) ([]byte, error)
	SerializeIdentityContents(identityContents *TPMIdentityContents) ([]byte, error)
	ConstructPubKey(publicKey *rsa.PublicKey) (*TPMPubKey, error)
	ConstructIdentityContents(publicKey *rsa.PublicKey) (*TPMIdentityContents, error)
	ConstructAsymCAContents(symKey *TPMSymmetricKey, identityKey *TPMPubKey) (*TPMAsymCAContents, error)
	SerializeAsymCAContents(asymCAContents *TPMAsymCAContents) ([]byte, error)
	SerializeSymmetricKey(symKey *TPMSymmetricKey) ([]byte, error)
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
// Link to spec: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf#page=119
func (u *DefaultTPM12Utils) ParseIdentityProof(idProofBytes []byte) (*TPMIdentityProof, error) {
	reader := bytes.NewReader(idProofBytes)
	result := &TPMIdentityProof{}

	// Read TPMStructVer fields (4 * 1 byte).
	tpmStructVer, err := u.ParseTpmStructVer(reader)
	if err != nil {
		return nil, err
	}
	result.TPMStructVer = *tpmStructVer

	// Read LabelArea size (4 bytes).
	labelAreaSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read LabelArea size: %w", err)
	}

	// Read IdentityBinding size (4 bytes).
	identityBindingSize, err := readNonZeroUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read IdentityBinding size: %w", err)
	}

	// Read EndorsementCredential size (4 bytes).
	endorsementCredentialSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read EndorsementCredential size: %w", err)
	}

	// Read PlatformCredential size (4 bytes).
	platformCredentialSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read PlatformCredential size: %w", err)
	}

	// Read ConformanceCredential size (4 bytes).
	conformanceCredentialSize, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read ConformanceCredential size: %w", err)
	}

	// Read AttestationIdentityKey (TPM_PUBKEY).
	aik, err := u.ParsePubKeyFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AttestationIdentityKey: %w", err)
	}
	result.AttestationIdentityKey = *aik

	// Read LabelArea.
	labelArea, err := readBytes(reader, labelAreaSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read LabelArea: %w", err)
	}
	result.LabelArea = labelArea

	// Read IdentityBinding.
	identityBinding, err := readBytes(reader, identityBindingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read IdentityBinding: %w", err)
	}
	result.IdentityBinding = identityBinding

	// Read EndorsementCredential.
	endorsementCredential, err := readBytes(reader, endorsementCredentialSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read EndorsementCredential: %w", err)
	}
	result.EndorsementCredential = endorsementCredential

	// Read PlatformCredential.
	platformCredential, err := readBytes(reader, platformCredentialSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read PlatformCredential: %w", err)
	}
	result.PlatformCredential = platformCredential

	// Read ConformanceCredential.
	conformanceCredential, err := readBytes(reader, conformanceCredentialSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read ConformanceCredential: %w", err)
	}
	result.ConformanceCredential = conformanceCredential

	if reader.Len() > 0 {
		return nil, fmt.Errorf("leftover bytes in TPM_IDENTITY_PROOF block after parsing: %d", reader.Len())
	}

	return result, nil
}

// ParsePubKeyFromReader parses a TPM_PUBKEY structure from a bytes.Reader.
// Link to spec: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf#page=103
func (u *DefaultTPM12Utils) ParsePubKeyFromReader(reader *bytes.Reader) (*TPMPubKey, error) {
	result := &TPMPubKey{}

	// Read AlgorithmParms (TPM_KEY_PARMS).
	algorithmParms, err := u.ParseKeyParmsFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AlgorithmParms: %w", err)
	}
	result.AlgorithmParms = *algorithmParms

	// Read PubKey (TPM_STORE_PUBKEY).
	PubKey, err := u.ParseStorePubKeyFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PubKey: %w", err)
	}
	result.PubKey = *PubKey

	return result, nil
}

// ParseStorePubKeyFromReader parses a TPM_STORE_PUBKEY structure from a bytes.Reader.
// Link to spec: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf#page=102
func (u *DefaultTPM12Utils) ParseStorePubKeyFromReader(reader *bytes.Reader) (*TPMStorePubKey, error) {
	result := &TPMStorePubKey{}

	// Read keyLength (4 bytes).
	keyLength, err := readUint32(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyLength: %w", err)
	}
	if keyLength == 0 {
		return nil, fmt.Errorf("keyLength cannot be zero")
	}
	result.KeyLength = keyLength

	// Read key.
	key, err := readBytes(reader, keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	result.Key = key

	return result, nil
}

// EncryptWithPublicKey encrypts data using a public key.
func (u *DefaultTPM12Utils) EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme TPMEncodingScheme) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is nil or empty")
	}
	if publicKey == nil || publicKey.N == nil {
		return nil, fmt.Errorf("publicKey or its modulus cannot be nil")
	}
	if publicKey.Size() == 0 {
		return nil, fmt.Errorf("publicKey size cannot be zero")
	}
	if algo != tpm12.AlgRSA {
		return nil, fmt.Errorf("unsupported algorithm: %v", tpm12.AlgMap[algo])
	}
	if encScheme != EsRSAEsOAEPSHA1MGF1 {
		return nil, fmt.Errorf("unsupported encoding scheme: %v", encScheme)
	}
	label := []byte(tpmLabel)
	// #nosec
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, data, label) /* #nosec G505 */
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

// NewAESCBCKey creates a new AES CBC symmetric key.
func (u *DefaultTPM12Utils) NewAESCBCKey(algo tpm12.Algorithm) (*TPMSymmetricKey, error) {
	var keyBytesSize int
	switch algo {
	case tpm12.AlgAES128:
		keyBytesSize = 16
	case tpm12.AlgAES192:
		keyBytesSize = 24
	case tpm12.AlgAES256:
		keyBytesSize = 32
	default:
		return nil, fmt.Errorf("unsupported algorithm for NewAESCBCKey: %v", tpm12.AlgMap[algo])
	}

	key := make([]byte, keyBytesSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	symKey := &TPMSymmetricKey{
		AlgID:     algo,
		EncScheme: EsSymCBCPKCS5,
		Key:       key,
	}
	return symKey, nil
}

// validateSymmetricKey validates the symmetric key parameters.
func validateSymmetricKey(symKey *TPMSymmetricKey) error {
	if symKey == nil {
		return fmt.Errorf("nil symmetric key")
	}
	if symKey.EncScheme != EsSymCBCPKCS5 {
		return fmt.Errorf("unsupported encoding scheme for symmetric key: %v", symKey.EncScheme)
	}
	acceptableAlgs := []tpm12.Algorithm{
		tpm12.AlgAES128,
		tpm12.AlgAES192,
		tpm12.AlgAES256,
	}
	if !slices.Contains(acceptableAlgs, symKey.AlgID) {
		return fmt.Errorf("unsupported algorithm for symmetric key: %v", symKey.AlgID)
	}
	return nil
}

// EncryptWithAES encrypts data using a symmetric key with AES CBC and returns the ciphertext and the
// key parameters.
func (u *DefaultTPM12Utils) EncryptWithAES(symKey *TPMSymmetricKey, data []byte) ([]byte, *TPMKeyParms, error) {
	if err := validateSymmetricKey(symKey); err != nil {
		return nil, nil, fmt.Errorf("invalid symmetric key: %w", err)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("data to encrypt cannot be empty")
	}

	cipherBlock, err := aes.NewCipher(symKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	blockSize := cipherBlock.BlockSize()
	if blockSize > math.MaxUint32 {
		return nil, nil, fmt.Errorf("symmetric block size (%d) exceeds maximum uint32 size", blockSize)
	}
	// #nosec
	blockSizeInUint32 := uint32(blockSize)

	if len(data) == 0 {
		return nil, nil, fmt.Errorf("data to encrypt cannot be empty")
	}

	// PKCS5 Padding: padding is the number of bytes to pad the data to the next multiple of the
	// block size.
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedData := append(data, padtext...)

	// Generate a random IV
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random IV: %w", err)
	}

	ciphertext := make([]byte, len(paddedData))
	encrypter := cipher.NewCBCEncrypter(cipherBlock, iv)
	encrypter.CryptBlocks(ciphertext, paddedData)

	kLen := len(symKey.Key)
	if kLen > math.MaxUint32 {
		return nil, nil, fmt.Errorf("symmetric key length (%d) exceeds maximum uint32 size", kLen)
	}
	keyLen := uint32(kLen)

	keyParms := &TPMKeyParms{
		AlgID:     symKey.AlgID,
		EncScheme: symKey.EncScheme,
		SigScheme: SsNone,
		Params: TPMParams{
			SymParams: &TPMSymmetricKeyParms{
				KeyLength: keyLen,
				BlockSize: blockSizeInUint32,
				IV:        iv,
			},
		},
	}

	return ciphertext, keyParms, nil
}

// DecryptWithSymmetricKey decrypts data using a private key.
func (u *DefaultTPM12Utils) DecryptWithSymmetricKey(ctx context.Context, symKey *TPMSymmetricKey, keyParams *TPMKeyParms, ciphertext []byte) ([]byte, error) {
	if keyParams.EncScheme != EsSymCBCPKCS5 {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedScheme, keyParams.EncScheme)
	}

	// Create a new AES cipher block from the symmetric key.
	cipherBlock, err := aes.NewCipher(symKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := keyParams.Params.SymParams.IV

	// The ciphertext must be a multiple of the block size.
	if len(ciphertext)%cipherBlock.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	// Create a new CBC decrypter.
	encrypter := cipher.NewCBCDecrypter(cipherBlock, iv)

	// Decrypt the data. The decrypted plaintext will be stored in the same
	// underlying array as the ciphertext.
	encrypter.CryptBlocks(ciphertext, ciphertext)

	// Unpad the decrypted plaintext using PKCS#5/PKCS#7.
	plaintext := ciphertext
	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) || padding == 0 {
		return nil, fmt.Errorf("%w: invalid value %d", ErrInvalidPadding, padding)
	}
	// Verify that all padding bytes are correct.
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if int(plaintext[i]) != padding {
			return nil, fmt.Errorf("%w: invalid padding byte found at position %d", ErrInvalidPadding, i)
		}
	}

	return plaintext[:len(plaintext)-padding], nil
}

// ConstructAsymCAContents constructs TPMAsymCAContents.
func (u *DefaultTPM12Utils) ConstructAsymCAContents(symKey *TPMSymmetricKey, identityKey *TPMPubKey) (*TPMAsymCAContents, error) {
	if err := validateSymmetricKey(symKey); err != nil {
		return nil, fmt.Errorf("invalid symmetric key: %w", err)
	}
	if identityKey == nil {
		return nil, fmt.Errorf("identityKey cannot be nil")
	}
	identityKeyBytes, err := u.SerializePubKey(identityKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize identityKey: %w", err)
	}
	// #nosec
	idDigest := sha1.Sum(identityKeyBytes)
	return &TPMAsymCAContents{
		SessionKey: *symKey,
		IDDigest:   idDigest,
	}, nil
}

// SerializeSymmetricKey serializes a TPMSymmetricKey to bytes.
func (u *DefaultTPM12Utils) SerializeSymmetricKey(symKey *TPMSymmetricKey) ([]byte, error) {
	if err := validateSymmetricKey(symKey); err != nil {
		return nil, fmt.Errorf("invalid symmetric key: %w", err)
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(symKey.AlgID)); err != nil {
		return nil, fmt.Errorf("failed to write the algorithm ID to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(symKey.EncScheme)); err != nil {
		return nil, fmt.Errorf("failed to write the encoding scheme to the buffer: %w", err)
	}

	keyLen := len(symKey.Key)
	if keyLen > math.MaxUint16 {
		return nil, fmt.Errorf("symmetric key data size (%d) exceeds maximum UINT16 size", keyLen)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(keyLen)); err != nil {
		return nil, fmt.Errorf("failed to write the key size to the buffer: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, symKey.Key); err != nil {
		return nil, fmt.Errorf("failed to write the key data to the buffer: %w", err)
	}
	return buf.Bytes(), nil
}

// SerializeAsymCAContents serializes a TPMAsymCAContents to bytes.
func (u *DefaultTPM12Utils) SerializeAsymCAContents(asymCAContents *TPMAsymCAContents) ([]byte, error) {
	if asymCAContents == nil {
		return nil, fmt.Errorf("asymCAContents cannot be nil")
	}

	sessionKeyBytes, err := u.SerializeSymmetricKey(&asymCAContents.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SessionKey: %w", err)
	}

	var buf bytes.Buffer
	buf.Write(sessionKeyBytes)
	err = binary.Write(&buf, binary.BigEndian, asymCAContents.IDDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to write asymCAContents.IDDigest to buffer: %w", err)
	}

	return buf.Bytes(), nil
}

// TpmPubKeyToRSAPubKey converts a TPMPubKey structure to an rsa.PublicKey.
func (u *DefaultTPM12Utils) TpmPubKeyToRSAPubKey(pubKey *TPMPubKey) (*rsa.PublicKey, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("pubKey is nil")
	}
	if pubKey.AlgorithmParms.AlgID != tpm12.AlgRSA {
		return nil, fmt.Errorf("unsupported algorithm: %v", pubKey.AlgorithmParms.AlgID)
	}
	if pubKey.AlgorithmParms.Params.RSAParams == nil {
		return nil, fmt.Errorf("RSA params are nil")
	}

	n := new(big.Int).SetBytes(pubKey.PubKey.Key)
	var e int
	if len(pubKey.AlgorithmParms.Params.RSAParams.Exponent) == 0 {
		e = 65537 // Default exponent
	} else {
		e = int(new(big.Int).SetBytes(pubKey.AlgorithmParms.Params.RSAParams.Exponent).Int64())
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// VerifySignatureWithRSAKey verifies a signature using an RSA public key.
// 'digest' is the result of hashing the original data with the 'hash' algorithm.
func (u *DefaultTPM12Utils) VerifySignatureWithRSAKey(ctx context.Context, pubKey *TPMPubKey, signature []byte, digest []byte) (bool, error) {
	rsaPubKey, err := u.TpmPubKeyToRSAPubKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse TPM public key: %w", err)
	}

	var hash crypto.Hash
	switch pubKey.AlgorithmParms.SigScheme {
	case SsRSASaPKCS1v15SHA1:
		hash = crypto.SHA1
	case SsRSASaPKCS1v15DER:
		// DER scheme doesn't mandate a specific hash, so we use the provided hash.
		// However, VerifyPKCS1v15 still needs the hash type.
		hash = crypto.Hash(0)
	default:
		return false, fmt.Errorf("unsupported signature scheme: %v", pubKey.AlgorithmParms.SigScheme)
	}
	if err := rsa.VerifyPKCS1v15(rsaPubKey, hash, digest, signature); err != nil {
		return false, fmt.Errorf("invalid PKCS1v15 signature for scheme %v: %w", pubKey.AlgorithmParms.SigScheme, err)
	}
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
