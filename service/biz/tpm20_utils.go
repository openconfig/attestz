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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	// #nosec

	tpm20 "github.com/google/go-tpm/tpm2"
)

// HMACChallenge contains the HMAC key for TPM 2.0 to import.
type HMACChallenge struct {
	// The restricted HMAC key public area (TPM2B_PUBLIC contents)
	HMACPubKey []byte
	// The wrapped restricted HMAC key sensitive area (TPM2B_PRIVATE contents)
	Duplicate []byte
	// The seed for the import of the restricted HMAC key under the EK (TPM2B_ENCRYPTED_SECRET contents)
	InSymSeed []byte
}

// TPM20Utils is an interface for TPM 2.0 utility functions.
// This interface was created to allow for mocking of the TPM 2.0 utility functions in unit tests
// since it is not possible to test the Rotate AIK flow with stubbed data.
type TPM20Utils interface {
	GenerateRestrictedHMACKey() (*tpm20.TPMTPublic, *tpm20.TPMTSensitive)
	CreateHMACChallenge(hmacPub *tpm20.TPMTPublic, hmacSensitive *tpm20.TPMTSensitive, ekPub *rsa.PublicKey) (*HMACChallenge, error)
}

// DefaultTPM20Utils is a concrete implementation of the TPM20Utils interface.
type DefaultTPM20Utils struct {
}

// GenerateRestrictedHMACKey generates a new HMAC key and emits the TPM public/private blobs.
func (u *DefaultTPM20Utils) GenerateRestrictedHMACKey() (*tpm20.TPMTPublic, *tpm20.TPMTSensitive) {
	// Generate the random obfuscation value and key
	obfuscate := make([]byte, 32)
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(obfuscate); err != nil {
		panic(fmt.Sprintf("GenerateRestrictedHMACKey: rand.Read() failed: %v", err))
	}
	if _, err := rand.Read(hmacKey); err != nil {
		panic(fmt.Sprintf("GenerateRestrictedHMACKey: rand.Read() failed: %v", err))
	}

	// Unique for a KEYEDHASH object is H_nameAlg(obfuscate | key)
	// See Part 1, "Public Area Creation"
	h := sha256.New()
	h.Write(obfuscate)
	h.Write(hmacKey)

	pub := &tpm20.TPMTPublic{
		Type:    tpm20.TPMAlgKeyedHash,
		NameAlg: tpm20.TPMAlgSHA256,
		ObjectAttributes: tpm20.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
			Restricted:   true,
			SignEncrypt:  true,
		},
		Parameters: tpm20.NewTPMUPublicParms(tpm20.TPMAlgKeyedHash, &tpm20.TPMSKeyedHashParms{
			Scheme: tpm20.TPMTKeyedHashScheme{
				Scheme: tpm20.TPMAlgHMAC,
				Details: tpm20.NewTPMUSchemeKeyedHash(tpm20.TPMAlgHMAC, &tpm20.TPMSSchemeHMAC{
					HashAlg: tpm20.TPMAlgSHA256,
				}),
			},
		}),
		Unique: tpm20.NewTPMUPublicID(tpm20.TPMAlgKeyedHash, &tpm20.TPM2BDigest{
			Buffer: h.Sum(nil),
		}),
	}

	priv := &tpm20.TPMTSensitive{
		SensitiveType: tpm20.TPMAlgKeyedHash,
		SeedValue: tpm20.TPM2BDigest{
			Buffer: obfuscate,
		},
		Sensitive: tpm20.NewTPMUSensitiveComposite(tpm20.TPMAlgKeyedHash, &tpm20.TPM2BSensitiveData{
			Buffer: hmacKey,
		}),
	}

	return pub, priv
}

// CreateHMACChallenge wraps a given HMAC key to the given EK.
// The verifier needs to remember the HMAC key for VerifyHMACChallenge later.
func (u *DefaultTPM20Utils) CreateHMACChallenge(hmacPub *tpm20.TPMTPublic, hmacSensitive *tpm20.TPMTSensitive, ekPub *rsa.PublicKey) (*HMACChallenge, error) {
	if hmacPub == nil {
		return nil, fmt.Errorf("CreateHMACChallenge: HMAC pub cannot be empty, %w", ErrNilInput)
	}
	if hmacSensitive == nil {
		return nil, fmt.Errorf("CreateHMACChallenge: HMAC sensitive cannot be empty, %w", ErrNilInput)
	}
	if ekPub == nil {
		return nil, fmt.Errorf("CreateHMACChallenge: EK pub key cannot be empty, %w", ErrNilInput)
	}

	rsa := tpm20.RSAEKTemplate
	rsaPub, err := rsa.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("CreateHMACChallenge: %w", err)
	}
	rsaParms, err := rsa.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("CreateHMACChallenge: %w", err)
	}
	rsaPub.Buffer = ekPub.N.Bytes()
	rsaParms.KeyBits = tpm20.TPMKeyBits(ekPub.N.BitLen()) // #nosec G115
	rsaParms.Exponent = uint32(ekPub.E)                   // #nosec G115

	name, err := tpm20.ObjectName(hmacPub)
	if err != nil {
		return nil, fmt.Errorf("CreateHMACChallenge: %w", err)
	}

	encap, err := tpm20.ImportEncapsulationKey(&rsa)
	if err != nil {
		return nil, fmt.Errorf("CreateHMACChallenge: %w", err)
	}

	duplicate, inSymSeed, err := tpm20.CreateDuplicate(rand.Reader, encap, name.Buffer, tpm20.Marshal(hmacSensitive))
	if err != nil {
		return nil, fmt.Errorf("CreateHMACChallenge: %w", err)
	}

	return &HMACChallenge{
		HMACPubKey: tpm20.Marshal(hmacPub),
		Duplicate:  duplicate,
		InSymSeed:  inSymSeed,
	}, nil
}
