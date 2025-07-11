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

// Package biz contains the infra-agnostic business logic of Enrollz Service hosted by the switch owner infra.
package biz

import (
	"context"
	"crypto"
	"crypto/rsa"

	tpm12 "github.com/google/go-tpm/tpm"
)

// Note: All the uint values in TPM_* structures in this file use big endian (network byte order).

// TPMKeyParms is the structure that contains the key parameters - TPM_KEY_PARMS from TPM 1.2 specification.
type TPMKeyParms struct {
	AlgID     tpm12.Algorithm // Algorithm identifier.
	EncScheme uint16          // Encryption scheme identifier.
	SigScheme uint16          // Signature scheme identifier.
	Params    []byte          // Algorithm specific parameters (e.g., RSA key parameters).
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
	EncScheme uint16
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

// ParseTPMSymmetricKey from bytes to TPMSymmetricKey.
func ParseSymmetricKey(_ []byte) (*TPMSymmetricKey, error) {
	// TODO: Implement the parsing of TPMSymmetricKey.
	// For now, we just return empty data.
	return &TPMSymmetricKey{}, nil
}

// ParseIdentityRequest from bytes to TPMIdentityReq
func ParseIdentityRequest(_ []byte) (*TPMIdentityReq, error) {
	// TODO: Implement the parsing of the identity request.
	// For now, we just return empty data.
	return &TPMIdentityReq{}, nil
}

func ParseIdentityProof(_ []byte) (*TPMIdentityProof, error) {
	// TODO: Implement the parsing of the identity proof.
	// For now, we just return empty data.
	return &TPMIdentityProof{}, nil
}

// EncryptWithPublicKey encrypts data using a public key.
func EncryptWithPublicKey(ctx context.Context, publicKey *rsa.PublicKey, data []byte, algo tpm12.Algorithm, encScheme uint16) ([]byte, error) {
	// TODO: Implement the encryption using a public key.
	// For now, we just return the data as is.
	return data, nil
}

// DecryptWithPrivateKey decrypts data using a private key.
func DecryptWithPrivateKey(ctx context.Context, privateKey *rsa.PrivateKey, data []byte, algo tpm12.Algorithm, encScheme uint16) ([]byte, error) {
	// TODO: Implement the decryption using a private key.
	// For now, we just return the data as is.
	return data, nil
}

// EncryptWithAes encrypts data using an AES key.
func EncryptWithAes(_ []byte, data []byte) ([]byte, error) {
	// TODO: Implement the encryption using AES-GCM.
	// For now, we just return the data as is.
	return data, nil
}

// DecryptWithSymmetricKey decrypts data using a private key.
func DecryptWithSymmetricKey(ctx context.Context, symKey []byte, data []byte, algo tpm12.Algorithm, encScheme uint16) ([]byte, error) {
	// TODO: Implement the decryption using a symmetric key.
	// For now, we just return the data as is.
	return data, nil
}

// VerifySignature verifies a signature using a public key.
func VerifySignature(ctx context.Context, pubKey []byte, signature []byte, data []byte, hash crypto.Hash) (bool, error) {
	// TODO: Implement the signature verification using a public key.
	// For now, we just return true.
	return true, nil
}
