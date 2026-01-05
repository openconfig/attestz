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
	"crypto/rand"
	"crypto/rsa"
	"strings"

	// #nosec
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	log "github.com/golang/glog"
	tpm12 "github.com/google/go-tpm/tpm"
	tpm20 "github.com/google/go-tpm/tpm2"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/prototext"
)

var (
	// ErrFailedToIssueOwnerCert is returned when the Switch Owner CA fails to issue an owner certificate.
	ErrFailedToIssueOwnerCert = errors.New("failed to issue owner cert")
	// ErrEmptyField is returned when a required field is empty.
	ErrEmptyField = errors.New("empty required field(s)")
	// ErrRotateOIakCert is returned when the device fails to rotate the oIAK and oIDevID certificates.
	ErrRotateOIakCert = errors.New("failed to rotate oIAK and oIDevID certs")
	// ErrNonceGeneration is returned when nonce generation fails.
	ErrNonceGeneration = errors.New("failed to generate nonce")
	// ErrNonceVerification is returned when nonce signature verification fails.
	ErrNonceVerification = errors.New("nonce verification failed")
	// ErrGetIakCert is returned when retrieving the IAK cert from the device fails.
	ErrGetIakCert = errors.New("failed to get IAK cert")
	// ErrCertVerification is returned when IAK or IDevID certificate verification fails.
	ErrCertVerification = errors.New("cert verification failed")
	// ErrInvalidRequest is returned when a request is invalid.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrAtomicRotationMismatch is returned when atomic cert rotation supported flag differs between control cards.
	ErrAtomicRotationMismatch = errors.New("atomic cert rotation supported flag differs between control cards")
	// ErrVerifyIdentity is returned when identity verification fails.
	ErrVerifyIdentity = errors.New("failed to verify identity")
	// ErrIssueAndRotateOwnerCerts is returned when issuing and rotating owner certs fails.
	ErrIssueAndRotateOwnerCerts = errors.New("failed to issue and rotate oIAK and oIDevID certs")
	// ErrKeyConversion is returned when key conversion fails.
	ErrKeyConversion = errors.New("failed to convert key")
	// ErrSerialMismatch is returned when the serial number in the CSR does not match the control card ID.
	ErrSerialMismatch = errors.New("serial number mismatch")
	// ErrInvalidResponse is returned when a response is invalid.
	ErrInvalidResponse = errors.New("invalid response")
)

// RSAkeySize2048 is the size of the RSA key used for TPM enrollment.
const RSAkeySize2048 = 2048

// IssueOwnerIakCertReq is the request to SwitchOwnerCaClient.IssueOwnerIakCert().
type IssueOwnerIakCertReq struct {
	// Identity fields of a given switch control card.
	CardID *cpb.ControlCardVendorId
	// PEM-encoded IAK public key.
	IakPubPem string
}

// IssueOwnerIakCertResp is the response to SwitchOwnerCaClient.IssueOwnerIakCert().
type IssueOwnerIakCertResp struct {
	// PEM-encoded owner IAK cert (signed by the switch owner CA).
	OwnerIakCertPem string
}

// IssueOwnerIDevIDCertReq is the request to SwitchOwnerCaClient.IssueOwnerIDevIDCert().
type IssueOwnerIDevIDCertReq struct {
	// Identity fields of a given switch control card.
	CardID *cpb.ControlCardVendorId
	// PEM-encoded IDevID public key.
	IDevIDPubPem string
}

// IssueOwnerIDevIDCertResp is the response to SwitchOwnerCaClient.IssueOwnerIDevIDCert().
type IssueOwnerIDevIDCertResp struct {
	// PEM-encoded owner IDevID cert (signed by the switch owner CA).
	OwnerIDevIDCertPem string
}

// IssueAikCertReq is the request to SwitchOwnerCaClient.IssueAikCert().
type IssueAikCertReq struct {
	// Identity fields of a given switch control card.
	CardID *cpb.ControlCardVendorId
	// PEM-encoded AIK public key.
	AikPubPem string
}

// IssueAikCertResp is the response to SwitchOwnerCaClient.IssueAikCert().
type IssueAikCertResp struct {
	// PEM-encoded AIK cert (signed by the switch owner CA).
	AikCertPem string
}

// SwitchOwnerCaClient is the client to communicate with the Switch Owner CA to issue oIAK and oIDevID
// certs.
type SwitchOwnerCaClient interface {
	// For a given switch control card ID, issue an oIAK PEM cert based on IAK public key PEM.
	IssueOwnerIakCert(ctx context.Context, req *IssueOwnerIakCertReq) (*IssueOwnerIakCertResp, error)

	// For a given switch control card ID, issue an oIDevID PEM cert based on IDevID public key PEM.
	IssueOwnerIDevIDCert(ctx context.Context, req *IssueOwnerIDevIDCertReq) (*IssueOwnerIDevIDCertResp, error)

	// For a given switch control card ID, issue an AIK PEM cert based on AIK public key PEM.
	IssueAikCert(ctx context.Context, req *IssueAikCertReq) (*IssueAikCertResp, error)
}

// EnrollzDeviceClient is a wrapper around gRPC `TpmEnrollzServiceClient` to allow customizable behavior.
//
// During initial install the device is expected to use IDevID cert to secure TLS connection. Once
// the initial install (includes TPM enrollment and attestation) is completed, the device is expected
// to obtain a set of "real" prod TLS credentials/certs and only rely on those instead of IDevID/oIDevID
// certs. This implies that Enrollz client should carefully choose the right/expected TLS trust anchors
// based on the device state/scenario (e.g. initial install vs oIAK cert rotation).
type EnrollzDeviceClient interface {
	// Returns `TpmEnrollzServiceClient.GetIakCert()` response.
	//
	// During initial device install scenario, for an active control card IDevID cert *must* come from
	// the TLS handshake. Even though the device may optionally also specify active card's IDevID cert
	// in the response payload, as part of this EnrollzDeviceClient.GetIakCert() implementation it is
	// expected that the caller will overwrite/set this response payload `idevid_cert` field with the
	// IDevID cert from the TLS handshake.
	//
	// As specified in https://github.com/openconfig/attestz README, it is impossible to talk directly to the
	// standby control card (so all calls to standby card are relayed by the active card), and it is a
	// responsibility of the active control card to authenticate standby card using IDevID handshake.
	// Thus, for standby card the best we can do in this case is fetch it's IDevID cert from the response
	// payload (as opposed to TLS handshake - what we do for an active card enrollment) which active card
	// is responsible to populate.
	GetIakCert(ctx context.Context, req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error)

	// Returns `TpmEnrollzServiceClient.RotateOIakCert()` response.
	RotateOIakCert(ctx context.Context, req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error)

	// Returns `TpmEnrollzServiceClient.RotateAIKCert()` response.
	RotateAIKCert(ctx context.Context, opts ...grpc.CallOption) (epb.TpmEnrollzService_RotateAIKCertClient, error)

	// Returns `TpmEnrollzServiceClient.GetControlCardVendorID()` response.
	GetControlCardVendorID(ctx context.Context, req *epb.GetControlCardVendorIDRequest) (*epb.GetControlCardVendorIDResponse, error)

	// Returns `TpmEnrollzServiceClient.Challenge()` response.
	Challenge(ctx context.Context, req *epb.ChallengeRequest) (*epb.ChallengeResponse, error)

	// Returns `TpmEnrollzServiceClient.GetIdevidCsr()` response.
	GetIdevidCsr(ctx context.Context, req *epb.GetIdevidCsrRequest) (*epb.GetIdevidCsrResponse, error)
}

// FetchEKReq is the request to fetch the EK Public Key from the RoT.
type FetchEKReq struct {
	// Serial number of the control card.
	Serial string
	// Supplier of the chassis.
	Supplier string
}

// FetchEKResp is the response to fetch the EK Public Key (or PPK) from the RoT.
type FetchEKResp struct {
	// EK (or PPK) Public Key.
	EkPublicKey *rsa.PublicKey
	// Key type: EK or PPK
	KeyType epb.Key
}

// ROTDBClient is a client to fetch the EK Public Key from the RoT.
type ROTDBClient interface {
	// FetchEK fetches the EK Public Key from the RoT.
	FetchEK(ctx context.Context, req *FetchEKReq) (*FetchEKResp, error)
}

// EnrollzInfraDeps is the infra-specific dependencies of this enrollz business logic lib. A service can create
// all these dependencies and wire them to the library on server start-up.
type EnrollzInfraDeps interface {
	// Client to communicate with Switch Owner CA to issue oIAK and oIDevID certs.
	SwitchOwnerCaClient

	// Client to communicate with the switch's enrollz endpoints.
	EnrollzDeviceClient

	// Parser and verifier of IAK and IDevID certs.
	TpmCertVerifier
}

// RotateAIKCertInfraDeps is the infra-specific dependencies of the RotateAIKCert business logic.
type RotateAIKCertInfraDeps interface {
	// Common enrollz dependencies.
	EnrollzInfraDeps

	// Client to fetch the EK Public Key from the RoT database.
	ROTDBClient

	// TPM 1.2 utility functions.
	TPM12Utils
}

// EnrollSwitchWithHMACChallengeInfraDeps is the infra-specific dependencies of the EnrollWithHMACChallenge business logic.
type EnrollSwitchWithHMACChallengeInfraDeps interface {
	// Common enrollz dependencies.
	EnrollzInfraDeps

	// Client to fetch the EK Public Key from the RoT database.
	ROTDBClient

	// TPM 2.0 utility functions.
	TPM20Utils
}

// EnrollControlCardReq is the request to EnrollControlCard().
type EnrollControlCardReq struct {
	// Selections of the switch control cards to enroll.
	ControlCardSelections []*cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	Deps EnrollzInfraDeps
	// Verification options for IAK and IDevID certs.
	CertVerificationOpts x509.VerifyOptions
	// SSL profile ID to which newly-issued Owner IDevID cert should be applied.
	SSLProfileID string
	// Experimental flag used for lab testing only. Skips oIDevID rotation.
	SkipOidevidRotate bool
	// Flag used to set the optional nonce and hash algorithm fields for nonce signature verification.
	SkipNonceExchange *bool
}

// validateEnrollControlCardReq verifies that EnrollControlCardReq request is valid.
func validateEnrollControlCardReq(req *EnrollControlCardReq) error {
	if req == nil {
		return fmt.Errorf("request EnrollControlCardReq is nil")
	}
	if len(req.ControlCardSelections) == 0 {
		return fmt.Errorf("field ControlCardSelections in EnrollControlCardReq request cannot be empty")
	}
	if len(req.ControlCardSelections) > 2 {
		return fmt.Errorf("field ControlCardSelections in EnrollControlCardReq request must have at most 2 control cards")
	}
	if req.Deps == nil {
		return fmt.Errorf("field Deps in EnrollControlCardReq request is nil")
	}

	return nil
}

// EnrollControlCard is a "client"/switch-owner side implementation of Enrollz service. This client-side logic
// is part of the switch owner infra/service and is expected to communicate with a device/switch (hosting
// enrollz gRPC endpoints) to verify its TPM-based identity and provision it with the switch-owner-issued,
// TPM-based attestation and TLS certs: Owner IAK and Owner IDevID certs, respectively. Switch owner is
// expected to TPM-enroll one or more switch control cards at a time, starting with an active card.
//
// More specifically, this function targets initial install/enrollment of the device. This means that the
// switch is expected to rely on the IDevID cert for establishing a secure TLS connection. Consumers
// of this function should carefully choose CA trust anchors in `x509.VerifyOptions` to include switch
// vendor CA root and intermediate certs that signed both IAK and IDevID certs. By the end of the workflow
// a given control card will obtain its first set of Owner IAK and Owner IDevID certs (signed by the switch
// owner CA).
func EnrollControlCard(ctx context.Context, req *EnrollControlCardReq) error {
	err := validateEnrollControlCardReq(req)
	if err != nil {
		err = fmt.Errorf("%w: invalid request EnrollControlCardReq to EnrollControlCard(): %v", ErrInvalidRequest, err)
		log.ErrorContext(ctx, err)
		return err
	}

	var cardDataList []ControlCardCertData
	var getIakCertRespList []*epb.GetIakCertResponse
	for _, selection := range req.ControlCardSelections {
		cardData, getIakCertResp, err := verifyIdentityWithVendorCerts(ctx, selection, req.Deps, req.CertVerificationOpts, req.SkipNonceExchange, true)
		if err != nil {
			err = fmt.Errorf("%w for control card %s: %w", ErrVerifyIdentity, prototext.Format(selection), err)
			log.ErrorContext(ctx, err)
			return err
		}
		cardDataList = append(cardDataList, *cardData)
		getIakCertRespList = append(getIakCertRespList, getIakCertResp)
	}

	if len(getIakCertRespList) == 2 {
		if getIakCertRespList[0].GetAtomicCertRotationSupported() != getIakCertRespList[1].GetAtomicCertRotationSupported() {
			return ErrAtomicRotationMismatch
		}
	}

	err = issueAndRotateOwnerCerts(ctx, req.Deps, cardDataList, req.SSLProfileID, req.SkipOidevidRotate,
		getIakCertRespList[0].GetAtomicCertRotationSupported())
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrIssueAndRotateOwnerCerts, err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Return a successful (no-error) response.
	return nil
}

type ControlCardCertData struct {
	ControlCardSelections *cpb.ControlCardSelection
	ControlCardID         *cpb.ControlCardVendorId
	IAKPubPem             string
	IDevIDPubPem          string
}

// verifyIdentityWithVendorCerts verifies the device's identity using vendor-issued certificates.
// It calls the device's GetIakCert method, validates the received IAK and optionally IDevID certificates,
// and verifies the nonce signature if provided. It returns the verified control card certificate
// data and the GetIakCertResponse from the device.
func verifyIdentityWithVendorCerts(ctx context.Context, controlCardSelection *cpb.ControlCardSelection, deps EnrollzInfraDeps, certVerificationOpts x509.VerifyOptions, skipNonceExchange *bool, verifyIDevID bool) (*ControlCardCertData, *epb.GetIakCertResponse, error) {
	getIakCertReq := &epb.GetIakCertRequest{ControlCardSelection: controlCardSelection}
	// Generate a nonce.
	if skipNonceExchange != nil && !*skipNonceExchange {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
		}
		getIakCertReq.Nonce = nonce
		getIakCertReq.HashAlgo = cpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA256.Enum()
	}
	getIakCertResp, err := deps.GetIakCert(ctx, getIakCertReq)
	if err != nil {
		return nil, nil, fmt.Errorf("%w with req=%s: %v", ErrGetIakCert, prototext.Format(getIakCertReq), err)
	}
	log.InfoContextf(ctx, "Successfully received from device GetIakCert() resp=%s for req=%s",
		prototext.Format(getIakCertResp), prototext.Format(getIakCertReq))

	// Validate and parse IDevID and IAK certs.
	var iakPubPem, idevidPubPem string
	if verifyIDevID {
		tpmCertVerifierReq := &VerifyIakAndIDevIDCertsReq{
			ControlCardID:        getIakCertResp.ControlCardId,
			IakCertPem:           getIakCertResp.IakCert,
			IDevIDCertPem:        getIakCertResp.IdevidCert,
			CertVerificationOpts: certVerificationOpts,
		}
		tpmCertVerifierResp, err := deps.VerifyIakAndIDevIDCerts(ctx, tpmCertVerifierReq)
		if err != nil {
			return nil, nil, fmt.Errorf("%w for IAK_cert_pem=%s and IDevID_cert_pem=%s: %v", ErrCertVerification, tpmCertVerifierReq.IakCertPem, tpmCertVerifierReq.IDevIDCertPem, err)
		}
		iakPubPem = tpmCertVerifierResp.IakPubPem
		idevidPubPem = tpmCertVerifierResp.IDevIDPubPem
		log.InfoContextf(ctx, "Successful TpmCertVerifier.VerifyIakAndIDevIDCerts() for control_card_id=%s, resp with IAK_pub_pem=%s and IDevID_pub_pem=%s",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.IakPubPem, tpmCertVerifierResp.IDevIDPubPem)
	} else {
		tpmCertVerifierReq := &VerifyTpmCertReq{
			ControlCardID:        getIakCertResp.ControlCardId,
			CertPem:              getIakCertResp.IakCert,
			CertVerificationOpts: certVerificationOpts,
		}
		tpmCertVerifierResp, err := deps.VerifyTpmCert(ctx, tpmCertVerifierReq)
		if err != nil {
			return nil, nil, fmt.Errorf("%w for IAK_cert_pem=%s: %v", ErrCertVerification, tpmCertVerifierReq.CertPem, err)
		}
		log.InfoContextf(ctx, "Successful TpmCertVerifier.VerifyTpmCert() for control_card_id=%s, resp with IAK_pub_pem=%s",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.PubPem)
		iakPubPem = tpmCertVerifierResp.PubPem
	}

	// Verify nonce signature if present.
	if len(getIakCertResp.NonceSignature) > 0 {
		resp, err := deps.VerifyNonceSignature(
			ctx, &VerifyNonceSignatureReq{
				Nonce:     getIakCertReq.Nonce,
				Signature: getIakCertResp.NonceSignature,
				HashAlgo:  *getIakCertReq.HashAlgo,
				IAKPubPem: iakPubPem,
			})
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrNonceVerification, err)
		}
		if !resp.IsValid {
			return nil, nil, ErrNonceVerification
		}
	}

	controlCardCertData := ControlCardCertData{
		ControlCardSelections: controlCardSelection,
		ControlCardID:         getIakCertResp.ControlCardId,
		IAKPubPem:             iakPubPem,
		IDevIDPubPem:          idevidPubPem,
	}

	return &controlCardCertData, getIakCertResp, nil
}

func issueOwnerIakCert(ctx context.Context, deps EnrollzInfraDeps, certData ControlCardCertData) (string, error) {
	issueOwnerIakCertReq := &IssueOwnerIakCertReq{
		CardID:    certData.ControlCardID,
		IakPubPem: certData.IAKPubPem,
	}
	issueOwnerIakCertResp, err := deps.IssueOwnerIakCert(ctx, issueOwnerIakCertReq)
	if err != nil {
		return "", fmt.Errorf("%w: type oIAK: %v", ErrFailedToIssueOwnerCert, err)
	}
	log.InfoContextf(ctx, "Successful Switch Owner CA IssueOwnerIakCert() for control_card_id=%s IAK_pub_pem=%s resp=%s",
		prototext.Format(certData.ControlCardID), certData.IAKPubPem, issueOwnerIakCertResp.OwnerIakCertPem)
	return issueOwnerIakCertResp.OwnerIakCertPem, nil
}

func issueOwnerIDevIDCert(ctx context.Context, deps EnrollzInfraDeps, certData ControlCardCertData, sslProfileID string, skipOidevidRotate bool) (string, error) {
	// TODO: add validation to ensure that IDevIDPubPem is not empty for active control card when skipOidevidRotate is false.
	if skipOidevidRotate || certData.IDevIDPubPem == "" {
		return "", nil
	}
	if sslProfileID == "" {
		return "", fmt.Errorf("%w: %s", ErrEmptyField, "SSLProfileID")
	}
	issueOwnerIDevIDCertReq := &IssueOwnerIDevIDCertReq{
		CardID:       certData.ControlCardID,
		IDevIDPubPem: certData.IDevIDPubPem,
	}
	issueOwnerIDevIDCertResp, err := deps.IssueOwnerIDevIDCert(ctx, issueOwnerIDevIDCertReq)
	if err != nil {
		return "", fmt.Errorf("%w: type oIDevID: %v", ErrFailedToIssueOwnerCert, err)
	}
	log.InfoContextf(ctx, "Successful Switch Owner CA IssueOwnerIDevIDCert() for control_card_id=%s IDevID_pub_pem=%s resp=%s",
		prototext.Format(certData.ControlCardID), certData.IDevIDPubPem, issueOwnerIDevIDCertResp.OwnerIDevIDCertPem)
	return issueOwnerIDevIDCertResp.OwnerIDevIDCertPem, nil
}

func rotateOIakCert(ctx context.Context, deps EnrollzInfraDeps, sslProfileID string, controlCardCerts []*epb.ControlCardCertUpdate, atomicCertRotationSupported bool) error {
	if len(controlCardCerts) == 0 {
		return fmt.Errorf("%w: %s", ErrEmptyField, "control card cert data list")
	}
	if atomicCertRotationSupported {
		// Rotate oIAK and oIDevID certs for all control cards atomically.
		// This is the preferred way to rotate certs going forward.
		rotateOIakCertReq := &epb.RotateOIakCertRequest{
			SslProfileId: sslProfileID,
			Updates:      controlCardCerts,
		}

		rotateOIakCertResp, err := deps.RotateOIakCert(ctx, rotateOIakCertReq)
		if err != nil {
			return fmt.Errorf("%w with req=%s: %v", ErrRotateOIakCert, rotateOIakCertReq, err)
		}
		log.InfoContextf(ctx, "Successfully received from device RotateOIakCert() for req=%s resp=%s",
			prototext.Format(rotateOIakCertReq), prototext.Format(rotateOIakCertResp))
	} else {
		// Rotate oIAK and oIDevID certs for each control card separately.
		for _, certData := range controlCardCerts {
			rotateOIakCertReq := &epb.RotateOIakCertRequest{
				SslProfileId:         sslProfileID,
				ControlCardSelection: certData.ControlCardSelection,
				OiakCert:             certData.OiakCert,
				OidevidCert:          certData.OidevidCert,
			}
			rotateOIakCertResp, err := deps.RotateOIakCert(ctx, rotateOIakCertReq)
			if err != nil {
				return fmt.Errorf("%w with req=%s: %v", ErrRotateOIakCert, rotateOIakCertReq, err)
			}
			log.InfoContextf(ctx, "Successfully received from device RotateOIakCert(%+v) = %+v",
				prototext.Format(rotateOIakCertReq), prototext.Format(rotateOIakCertResp))
		}
	}
	return nil
}

// issueAndRotateOwnerCerts issues oIAK and oIDevID certs for each control card and rotates them on the device.
func issueAndRotateOwnerCerts(ctx context.Context, deps EnrollzInfraDeps, certDataList []ControlCardCertData, sslProfileID string, skipOidevidRotate bool, atomicCertRotationSupported bool) error {
	if len(certDataList) == 0 {
		return fmt.Errorf("%w: %s", ErrEmptyField, "card data list")
	}
	if deps == nil {
		return fmt.Errorf("%w: %s", ErrEmptyField, "deps")
	}

	// Issue oIAK and oIDevID certs for each control card.
	var controlCardCerts []*epb.ControlCardCertUpdate
	for _, certData := range certDataList {
		var validationErrs []string
		if certData.ControlCardID == nil {
			validationErrs = append(validationErrs, "ControlCardID")
		}
		if certData.ControlCardSelections == nil {
			validationErrs = append(validationErrs, "ControlCardSelections")
		}
		if certData.IAKPubPem == "" {
			validationErrs = append(validationErrs, "IAKPubPem")
		}
		if len(validationErrs) > 0 {
			return fmt.Errorf("%w: %s", ErrEmptyField, strings.Join(validationErrs, ", "))
		}
		oidevidCert, err := issueOwnerIDevIDCert(ctx, deps, certData, sslProfileID, skipOidevidRotate)
		if err != nil {
			return err
		}
		oiakCert, err := issueOwnerIakCert(ctx, deps, certData)
		if err != nil {
			return err
		}

		controlCardCerts = append(controlCardCerts, &epb.ControlCardCertUpdate{
			ControlCardSelection: certData.ControlCardSelections,
			OiakCert:             oiakCert,
			OidevidCert:          oidevidCert,
		})
	}

	return rotateOIakCert(ctx, deps, sslProfileID, controlCardCerts, atomicCertRotationSupported)
}

// RotateOwnerIakCertReq is the request to RotateOwnerIakCert().
type RotateOwnerIakCertReq struct {
	// Selection of a specific switch control card.
	ControlCardSelections []*cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	Deps EnrollzInfraDeps
	// Verification options for IAK cert.
	CertVerificationOpts x509.VerifyOptions
	// Flag used to set the optional nonce and hash algorithm fields for nonce signature verification.
	SkipNonceExchange *bool
}

// validateRotateOwnerIakCert verifies that RotateOwnerIakCertReq request is valid.
func validateRotateOwnerIakCert(req *RotateOwnerIakCertReq) error {
	if req == nil {
		return fmt.Errorf("request RotateOwnerIakCertReq is nil")
	}
	if req.Deps == nil {
		return fmt.Errorf("field Deps in RotateOwnerIakCertReq request is nil")
	}
	if len(req.ControlCardSelections) == 0 {
		return fmt.Errorf("field ControlCardSelections in RotateOwnerIakCertReq request cannot be empty")
	}
	if len(req.ControlCardSelections) > 2 {
		return fmt.Errorf("field ControlCardSelections in RotateOwnerIakCertReq request must have at most 2 control cards")
	}

	return nil
}

// RotateOwnerIakCert is a "client"/switch-owner side implementation of Enrollz service. This client-side logic
// is part of the switch owner infra/service and is expected to communicate with a device/switch (hosting
// enrollz gRPC endpoints) to verify its TPM-based identity and provision it with the switch-owner-issued,
// TPM-based attestation Owner IAK cert. Switch owner is expected to TPM-enroll one switch control card
// at a time, starting with an active card.
//
// More specifically, this function targets rotation of the Owner IAK cert in a post-install scenario.
// This means that the switch may NOT be using (o/)IDevID TLS certs anymore, and instead relies on a "real"
// prod mTLS cert that was issued to the switch after its first successful attestation. Thus, this function
// only assumes the presence of an IAK cert in the response from the device. Consumers of this function
// should carefully choose CA trust anchors in `x509.VerifyOptions` to include switch vendor CA root and
// intermediate certs that signed the IAK cert. By the end of the workflow a given control card will obtain a
// new (rotated) Owner IAK cert (signed by the switch owner CA).
func RotateOwnerIakCert(ctx context.Context, req *RotateOwnerIakCertReq) error {
	err := validateRotateOwnerIakCert(req)
	if err != nil {
		err = fmt.Errorf("%w: invalid request to RotateOwnerIakCert(): %v", ErrInvalidRequest, err)
		log.ErrorContext(ctx, err)
		return err
	}

	var cardDataList []ControlCardCertData
	var getIakCertRespList []*epb.GetIakCertResponse
	for _, selection := range req.ControlCardSelections {
		cardData, getIakCertResp, err := verifyIdentityWithVendorCerts(ctx, selection, req.Deps, req.CertVerificationOpts, req.SkipNonceExchange, false)
		if err != nil {
			err = fmt.Errorf("%w for control card %s: %w", ErrVerifyIdentity, prototext.Format(selection), err)
			log.ErrorContext(ctx, err)
			return err
		}
		cardDataList = append(cardDataList, *cardData)
		getIakCertRespList = append(getIakCertRespList, getIakCertResp)
	}

	if len(getIakCertRespList) == 2 {
		if getIakCertRespList[0].GetAtomicCertRotationSupported() != getIakCertRespList[1].GetAtomicCertRotationSupported() {
			log.ErrorContext(ctx, ErrAtomicRotationMismatch)
			return ErrAtomicRotationMismatch
		}
	}

	err = issueAndRotateOwnerCerts(ctx, req.Deps, cardDataList, "", true, getIakCertRespList[0].GetAtomicCertRotationSupported())
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrIssueAndRotateOwnerCerts, err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Return a successful (no-error) response.
	return nil
}

// RotateAIKCertReq is the request to RotateAIKCert().
type RotateAIKCertReq struct {
	// Selection of a specific switch control card.
	ControlCardSelection *cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	Deps RotateAIKCertInfraDeps
}

// validateRotateAIKCertReq verifies that RotateAIKCertReq request is valid.
func validateRotateAIKCertReq(req *RotateAIKCertReq) error {
	if req == nil {
		return fmt.Errorf("request RotateAIKCertReq is nil")
	}
	if req.ControlCardSelection == nil {
		return fmt.Errorf("field ControlCardSelection in RotateAIKCertReq request is nil")
	}
	if req.Deps == nil {
		return fmt.Errorf("field Deps in RotateAIKCertReq request is nil")
	}
	return nil
}

// RotateAIKCert is a "client"/switch-owner side implementation of Enrollz service for TPM 1.2 devices.
// This function handles the entire TPM 1.2 enrollment flow, including generating an issuer key pair,
// interacting with the device's TPM 1.2, and handling the encryption and decryption of the AIK certificate.
func RotateAIKCert(ctx context.Context, req *RotateAIKCertReq) error {
	err := validateRotateAIKCertReq(req)
	if err != nil {
		err = fmt.Errorf("RotateAIKCert(): invalid request: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	// Generate Issuer Key Pair
	issuerPrivateKey, err := rsa.GenerateKey(rand.Reader, RSAkeySize2048)
	if err != nil {
		err = fmt.Errorf("failed to generate issuer key pair: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	issuerPublicKey := &issuerPrivateKey.PublicKey

	// Send issuer_public_key to the device.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(issuerPublicKey)
	if err != nil {
		err = fmt.Errorf("failed to marshal issuer public key: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	rotateAIKCertReq := &epb.RotateAIKCertRequest{
		Value: &epb.RotateAIKCertRequest_IssuerPublicKey{
			IssuerPublicKey: publicKeyBytes,
		},
		ControlCardSelection: req.ControlCardSelection,
	}

	stream, err := req.Deps.RotateAIKCert(ctx)
	if err != nil {
		err = fmt.Errorf("failed to initiate RotateAIKCert stream: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	if err := stream.Send(rotateAIKCertReq); err != nil {
		err = fmt.Errorf("failed to send issuer public key to the device: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Handle application_identity_request
	resp, err := stream.Recv()
	if err != nil {
		err = fmt.Errorf("failed to receive application_identity_request from the device: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	applicationIdentityRequestBytes := resp.GetApplicationIdentityRequest()
	if len(applicationIdentityRequestBytes) == 0 {
		err = fmt.Errorf("application_identity_request is empty")
		log.ErrorContext(ctx, err)
		return err
	}

	// Parse application_identity_request
	applicationIdentityRequest, err := req.Deps.ParseIdentityRequest(applicationIdentityRequestBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse application_identity_request: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Decrypt AsymBlob to get a symmetric key using issuer private key
	symKeyBytes, err := req.Deps.DecryptWithPrivateKey(ctx, issuerPrivateKey, applicationIdentityRequest.AsymBlob, applicationIdentityRequest.AsymAlgorithm.AlgID, applicationIdentityRequest.AsymAlgorithm.EncScheme)
	if err != nil {
		err = fmt.Errorf("failed to decrypt AsymBlob: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	// TODO: parse symKeyBytes into TPMSymmetricKey
	symKey, err := req.Deps.ParseSymmetricKey(symKeyBytes)
	if err != nil {
		err = fmt.Errorf("failed to parse symmetric key: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Decrypt SymBlob to get Identity proof using symmetric key
	identityProofBytes, err := req.Deps.DecryptWithSymmetricKey(ctx, symKey, &applicationIdentityRequest.SymAlgorithm, applicationIdentityRequest.SymBlob)
	if err != nil {
		err = fmt.Errorf("failed to decrypt SymBlob: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Parse Identity proof
	identityProof, err := req.Deps.ParseIdentityProof(identityProofBytes)
	if err != nil {
		err = fmt.Errorf("failed to decrypt identity proof: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Construct TPM_IDENTITY_CONTENTS
	identityContents, err := req.Deps.ConstructIdentityContents(issuerPublicKey, &identityProof.AttestationIdentityKey)
	if err != nil {
		return fmt.Errorf("failed to construct identity contents: %w", err)
	}

	// Serialize the identity contents.
	identityContentsBytes, err := req.Deps.SerializeIdentityContents(identityContents)
	if err != nil {
		return fmt.Errorf("failed to serialize identity contents: %w", err)
	}

	// #nosec Hash the serialized identity contents using SHA1.
	hasher := sha1.New()
	if _, err := hasher.Write(identityContentsBytes); err != nil {
		return fmt.Errorf("failed to write to hasher: %w", err)
	}
	identityContentsHash := hasher.Sum(nil)

	// Verify signature of TPM_IDENTITY_CONTENTS in Identity proof using AIK pub key
	isValid, err := req.Deps.VerifySignatureWithRSAKey(ctx, &identityProof.AttestationIdentityKey, identityProof.IdentityBinding, identityContentsHash)
	if err != nil {
		err = fmt.Errorf("failed to verify identity contents signature: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	if !isValid {
		err = fmt.Errorf("identity contents signature is not valid: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Get AIK public key from identityProof and convert to PEM.
	aikPubKeyRsa, err := req.Deps.TpmPubKeyToRSAPubKey(&identityProof.AttestationIdentityKey)
	if err != nil {
		err = fmt.Errorf("failed to convert AIK TPM pub key to RSA pub key: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	aikPubKeyPkix, err := x509.MarshalPKIXPublicKey(aikPubKeyRsa)
	if err != nil {
		err = fmt.Errorf("failed to marshal AIK public key to PKIX: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: aikPubKeyPkix, // Use the marshaled PKIX bytes
	}
	aikPubPem := pem.EncodeToMemory(pemBlock)

	// Issue AIK cert
	issueAikCertResp, err := req.Deps.IssueAikCert(ctx, &IssueAikCertReq{
		CardID:    resp.GetControlCardId(),
		AikPubPem: string(aikPubPem),
	})
	if err != nil {
		err = fmt.Errorf("failed to issue AIK certificate: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Create a new AES CBC key.
	aesCBCKey, err := req.Deps.NewAESCBCKey(tpm12.AlgAES256)
	if err != nil {
		err = fmt.Errorf("failed to create AES CBC key: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Encrypt AIK cert with AES key.
	encryptedAikCert, symKeyParms, err := req.Deps.EncryptWithAES(aesCBCKey, []byte(issueAikCertResp.AikCertPem))
	if err != nil {
		err = fmt.Errorf("failed to encrypt AIK certificate: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Construct TPM_SYM_CA_ATTESTATION and serialize it.
	symCAAttestation := &TPMSymCAAttestation{
		Algorithm:  *symKeyParms,
		Credential: encryptedAikCert,
	}
	aikCertBlob, err := req.Deps.SerializeSymCAAttestation(symCAAttestation)
	if err != nil {
		err = fmt.Errorf("failed to serialize TPM_SYM_CA_ATTESTATION: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Construct and serialize TPMAsymCAContents using AES CBC key and AIK pub key.
	asymCAContents, err := req.Deps.ConstructAsymCAContents(aesCBCKey, &identityProof.AttestationIdentityKey)
	if err != nil {
		err = fmt.Errorf("failed to construct AsymCAContents: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	asymCAContentsBytes, err := req.Deps.SerializeAsymCAContents(asymCAContents)
	if err != nil {
		err = fmt.Errorf("failed to serialize AsymCAContents: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Get EK Public Key from RoT database.
	fetchEKResp, err := req.Deps.FetchEK(ctx, &FetchEKReq{
		Serial:   resp.GetControlCardId().GetChassisSerialNumber(),
		Supplier: resp.GetControlCardId().GetChassisManufacturer(),
	})
	if err != nil {
		err = fmt.Errorf("failed to fetch EK public key for control card %s: %w", prototext.Format(resp.GetControlCardId()), err)
		log.ErrorContext(ctx, err)
		return err
	}
	if fetchEKResp == nil {
		err = fmt.Errorf("failed to fetch EK public key: RoT database returned an empty response")
		log.ErrorContext(ctx, err)
		return err
	}
	ekPublicKey := fetchEKResp.EkPublicKey
	ekAlgo := tpm12.AlgRSA
	ekEncScheme := EsRSAEsOAEPSHA1MGF1

	// Encrypt TPMAsymCAContents, containing the AES key, with the EK public key.
	symKeyBlob, err := req.Deps.EncryptWithPublicKey(ctx, ekPublicKey, asymCAContentsBytes, ekAlgo, ekEncScheme)
	if err != nil {
		err = fmt.Errorf("failed to encrypt TPMAsymCAContents: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Send encrypted data
	issuerCertPayload := &epb.RotateAIKCertRequest_IssuerCertPayload{
		SymmetricKeyBlob: symKeyBlob,
		AikCertBlob:      aikCertBlob,
	}
	rotateAIKCertReq = &epb.RotateAIKCertRequest{
		Value:                &epb.RotateAIKCertRequest_IssuerCertPayload_{IssuerCertPayload: issuerCertPayload},
		ControlCardSelection: req.ControlCardSelection,
	}
	if err := stream.Send(rotateAIKCertReq); err != nil {
		err = fmt.Errorf("failed to send encrypted AIK certificate to the device: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}

	// Handle AIK Cert Confirmation
	resp, err = stream.Recv()
	if err != nil {
		err = fmt.Errorf("failed to receive AIK certificate from the device: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	deviceAikCert := resp.GetAikCert()
	if len(deviceAikCert) == 0 {
		err = fmt.Errorf("device AIK cert is empty")
		log.ErrorContext(ctx, err)
		return err
	}

	// Compare AIK Certs
	if issueAikCertResp.AikCertPem != deviceAikCert {
		err = fmt.Errorf("AIK certificates do not match")
		log.ErrorContext(ctx, err)
		return err
	}

	// Finalize Enrollment
	rotateAIKCertReq = &epb.RotateAIKCertRequest{
		Value: &epb.RotateAIKCertRequest_Finalize{
			Finalize: true,
		},
		ControlCardSelection: req.ControlCardSelection,
	}
	if err := stream.Send(rotateAIKCertReq); err != nil {
		err = fmt.Errorf("failed to send finalize message to the device: %w", err)
		log.ErrorContext(ctx, err)
		return err
	}
	if _, err := stream.Recv(); err != io.EOF {
		// Close the stream.
		err = stream.CloseSend()
		if err != nil {
			err = fmt.Errorf("failed to finalize the enrollment: %w", err)
			log.ErrorContext(ctx, err)
			return err
		}
	}
	log.InfoContext(ctx, "Successfully finalized TPM 1.2 enrollment")
	return nil
}

// EnrollSwitchWithHMACChallengeReq is the request to EnrollWithHMACChallenge().
type EnrollSwitchWithHMACChallengeReq struct {
	// List of switch control cards to be enrolled.
	ControlCardSelections []*cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	Deps EnrollSwitchWithHMACChallengeInfraDeps
	// SSL profile ID to which newly-issued Owner IDevID cert should be applied.
	SSLProfileID string
}

// EnrollSwitchWithHMACChallenge enrolls a list of switch TPM 2.0 control cards using an HMAC challenge.
// For each control card, it verifies the identity using an HMAC challenge. Then it issues and
// rotates the IAK and OIDevID certificates for all control cards atomically.
func EnrollSwitchWithHMACChallenge(ctx context.Context, req *EnrollSwitchWithHMACChallengeReq) error {
	// validate the request
	if req == nil {
		err := fmt.Errorf("%w: request EnrollWithHMACChallengeReq is nil", ErrInvalidRequest)
		log.ErrorContext(ctx, err)
		return err
	}
	if len(req.ControlCardSelections) < 1 || len(req.ControlCardSelections) > 2 {
		err := fmt.Errorf("%w: field ControlCardSelections in EnrollSwitchWithHMACChallengeReq request must have 1 or 2 control cards, got %d", ErrInvalidRequest, len(req.ControlCardSelections))
		log.ErrorContext(ctx, err)
		return err
	}
	if req.Deps == nil {
		err := fmt.Errorf("%w: field Deps in EnrollWithHMACChallengeReq request cannot be nil", ErrInvalidRequest)
		log.ErrorContext(ctx, err)
		return err
	}

	var controlCardCertUpdates []ControlCardCertData

	// Verify identity with HMAC challenge for each control card.
	for _, controlCardSelection := range req.ControlCardSelections {
		cardID, iakPubKey, idevidPubKey, err := verifyIdentityWithHMACChallenge(ctx, controlCardSelection, req.Deps)
		if err != nil {
			err = fmt.Errorf("%w: failed to verify Identity with HMAC Challenge: %v", ErrVerifyIdentity, err)
			log.ErrorContext(ctx, err)
			return err
		}

		var errs []error
		iakPubPem, err := req.Deps.TPMTPublicToPEM(iakPubKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: failed to convert IAK public key to PEM: %v", ErrKeyConversion, err))
		}
		idevidPubPem, err := req.Deps.TPMTPublicToPEM(idevidPubKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: failed to convert IDevID public key to PEM: %v", ErrKeyConversion, err))
		}
		if len(errs) > 0 {
			err = errors.Join(errs...)
			log.ErrorContext(ctx, err)
			return err
		}

		controlCardCertUpdates = append(controlCardCertUpdates, ControlCardCertData{
			ControlCardSelections: controlCardSelection,
			ControlCardID:         cardID,
			IAKPubPem:             iakPubPem,
			IDevIDPubPem:          idevidPubPem,
		})
	}

	if err := issueAndRotateOwnerCerts(ctx, req.Deps, controlCardCertUpdates, req.SSLProfileID, false, true); err != nil {
		err = fmt.Errorf("%w: %v", ErrIssueAndRotateOwnerCerts, err)
		log.ErrorContext(ctx, err)
		return err
	}
	return nil
}

// verifyIdentityWithHMACChallenge verifies the identity of the switch using an HMAC challenge for
// TPM 2.0 devices that do not have an IDevID cert provisioned. This is typically used during
// the initial enrollment of a device where a secure channel cannot be established using
// an IDevID certificate. The process involves:
//  1. Fetching the Endorsement Key (EK) public key from a Rotate-of-Trust (RoT) database.
//  2. Generating a restricted HMAC key and securely wrapping it to the fetched EK public key.
//  3. Sending the wrapped HMAC key as a challenge to the device's TPM.
//  4. The TPM uses the EK private key to unwrap the HMAC key and generates a challenge response.
//  5. The service verifies the TPM's HMAC response to confirm possession of the EK private key.
//  6. The service also verifies the integrity of the IAK public key and the IDevID CSR
//     received from the device.
func verifyIdentityWithHMACChallenge(ctx context.Context, controlCardSelection *cpb.ControlCardSelection, deps EnrollSwitchWithHMACChallengeInfraDeps) (controlCardID *cpb.ControlCardVendorId, iakPub *tpm20.TPMTPublic, idevidPub *tpm20.TPMTPublic, err error) {
	// validate the request
	if controlCardSelection == nil {
		return nil, nil, nil, fmt.Errorf("%w: controlCardSelection cannot be nil", ErrInvalidRequest)
	}

	if deps == nil {
		return nil, nil, nil, fmt.Errorf("%w: deps cannot be nil", ErrInvalidRequest)
	}

	// Get Control Card Vendor ID from the TPM.
	// TODO: add more validations on controlCardSelection
	controlCardVendorID, err := deps.GetControlCardVendorID(ctx, &epb.GetControlCardVendorIDRequest{
		ControlCardSelection: controlCardSelection,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get control card vendor ID: %w", err)
	}

	// Get EK Public Key (or PPK) from RoT database.
	fetchEKResp, err := fetchEKPublicKey(ctx, deps, controlCardVendorID.GetControlCardId())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to fetch EK: %w", err)
	}

	// Create HMAC Challenge request.
	hmacChallenge, hmacSensitive, err := createHMACChallenge(deps, fetchEKResp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create HMAC challenge: %w", err)
	}

	challengeResp, err := deps.Challenge(ctx, &epb.ChallengeRequest{ControlCardSelection: controlCardSelection, Challenge: hmacChallenge, Key: fetchEKResp.KeyType})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to challenge the TPM: %w", err)
	}
	hmacResp := challengeResp.GetChallengeResp()

	certifyInfo2B, err := tpm20.Unmarshal[tpm20.TPM2BAttest](hmacResp.GetIakCertifyInfo())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal IAK Certify Info into TPM2B_ATTEST: %w", err)
	}
	iakCertifyInfo, err := certifyInfo2B.Contents()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get IAK Certify Info contents: %w", err)
	}

	// Verify HMAC Challenge response from the TPM.
	err = deps.VerifyHMAC(tpm20.Marshal(iakCertifyInfo), hmacResp.GetIakCertifyInfoSignature(), hmacSensitive)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify HMAC Challenge response: %w", err)
	}

	// Verify IAK Public Key.
	iakPubKey, err := verifyIAKKey(deps, hmacResp)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify IAK public key: %w", err)
	}

	// Get IDevID CSR from the TPM.
	keyTemplate := epb.KeyTemplate_KEY_TEMPLATE_ECC_NIST_P384
	getIDevIDCSRResp, err := deps.GetIdevidCsr(ctx, &epb.GetIdevidCsrRequest{
		ControlCardSelection: controlCardSelection,
		Key:                  fetchEKResp.KeyType,
		KeyTemplate:          keyTemplate,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get IDevID CSR: %w", err)
	}

	// Verify IDevID Public Key and CSR.
	idevidPubKey, err := verifyIdevidKeyAndCsr(deps, fetchEKResp, iakPubKey, getIDevIDCSRResp, keyTemplate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify IDevID key and CSR: %w", err)
	}
	return controlCardVendorID.GetControlCardId(), iakPubKey, idevidPubKey, nil
}

// fetchEKPublicKey fetches the EK Public Key from the RoT database.
func fetchEKPublicKey(ctx context.Context, client ROTDBClient, cardID *cpb.ControlCardVendorId) (*FetchEKResp, error) {
	fetchEKResp, err := client.FetchEK(ctx, &FetchEKReq{
		Serial:   cardID.GetChassisSerialNumber(),
		Supplier: cardID.GetChassisManufacturer(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EK public key for control card %s: %w", prototext.Format(cardID), err)
	}
	if fetchEKResp == nil {
		return nil, fmt.Errorf("%w: RoT database returned an empty FetchEKResp for control card %s", ErrInvalidResponse, prototext.Format(cardID))
	}
	return fetchEKResp, nil
}

// createHMACChallenge creates an HMAC and wraps it to the EK and returns a epb.HMACChallenge struct.
func createHMACChallenge(deps TPM20Utils, fetchEKResp *FetchEKResp) (*epb.HMACChallenge, *tpm20.TPMTSensitive, error) {
	if deps == nil {
		return nil, nil, fmt.Errorf("%w: deps cannot be nil", ErrInvalidRequest)
	}
	// Generate restricted HMAC key.
	hmacPub, hmacSensitive, err := deps.GenerateRestrictedHMACKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate restricted HMAC key: %w", err)
	}

	if fetchEKResp == nil {
		return nil, nil, fmt.Errorf("%w: fetchEKResp cannot be nil", ErrInvalidRequest)
	}
	// Wrap HMAC key to EK public key.
	duplicate, inSymSeed, err := deps.WrapHMACKeytoRSAPublicKey(fetchEKResp.EkPublicKey, hmacPub, hmacSensitive)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap HMAC key to EK public key: %w", err)
	}

	challengeReq := &epb.HMACChallenge{
		HmacPubKey: tpm20.Marshal(hmacPub),
		Duplicate:  duplicate,
		InSymSeed:  inSymSeed,
	}

	return challengeReq, hmacSensitive, nil
}

// verifyIAKKey verifies the IAK Certify Info and IAK Attributes.
func verifyIAKKey(deps TPM20Utils, hmacChallengeResp *epb.HMACChallengeResponse) (*tpm20.TPMTPublic, error) {
	if deps == nil {
		return nil, fmt.Errorf("%w: deps cannot be nil", ErrInvalidRequest)
	}
	if hmacChallengeResp == nil {
		return nil, fmt.Errorf("%w: hmacChallengeResp cannot be nil", ErrInvalidRequest)
	}
	// unmarshall IAK public key (TPMT_PUBLIC) and verify its attributes.
	iakPubKey, err := deps.VerifyIAKAttributes(hmacChallengeResp.IakPub)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IAK attributes: %w", err)
	}

	certifyInfo, err := tpm20.Unmarshal[tpm20.TPM2BAttest](hmacChallengeResp.IakCertifyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal IAK Certify Info: %w", err)
	}
	iakCertifyInfo, err := certifyInfo.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAK Certify Info contents: %w", err)
	}
	// Verify IAK Certify Info.
	err = deps.VerifyCertifyInfo(iakCertifyInfo, iakPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IAK Certify Info: %w", err)
	}

	return iakPubKey, nil
}

// verifyIdevidKey verifies the IDevID Certify Info, IDevID Attributes, and the IDevID CSR signature.
func verifyIdevidKeyAndCsr(deps TPM20Utils, fetchEKResp *FetchEKResp, iakPubKey *tpm20.TPMTPublic, getIdevidCsrResponse *epb.GetIdevidCsrResponse, keyTemplate epb.KeyTemplate) (*tpm20.TPMTPublic, error) {
	if getIdevidCsrResponse == nil {
		return nil, fmt.Errorf("%w: getIdevidCsrResponse cannot be nil", ErrInvalidRequest)
	}
	csrResponse := getIdevidCsrResponse.GetCsrResponse()
	if csrResponse == nil {
		return nil, fmt.Errorf("%w: csrResponse cannot be nil", ErrInvalidRequest)
	}
	controlCardID := getIdevidCsrResponse.GetControlCardId()
	if controlCardID == nil {
		return nil, fmt.Errorf("%w: controlCardID cannot be nil", ErrInvalidRequest)
	}
	if deps == nil {
		return nil, fmt.Errorf("%w: deps cannot be nil", ErrInvalidRequest)
	}
	// ParseTCGCSRIDevIDContent will verify that SignCertifyInfo, SignCertifyInfoSignature and IDevIDPub and are not empty.
	idevidCsrContents, err := deps.ParseTCGCSRIDevIDContent(csrResponse.CsrContents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IDevID CSR contents: %w", err)
	}
	err = deps.VerifyTPMTSignature(tpm20.Marshal(idevidCsrContents.SignCertifyInfo), &idevidCsrContents.SignCertifyInfoSignature, iakPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IDevID certify info signature using IAK public key: %w", err)
	}

	err = deps.VerifyCertifyInfo(&idevidCsrContents.SignCertifyInfo, &idevidCsrContents.IDevIDPub)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IDevID certify info: %w", err)
	}

	err = deps.VerifyIdevidAttributes(&idevidCsrContents.IDevIDPub, keyTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IDevID attributes: %w", err)
	}

	idevidCsrSignature, err := tpm20.Unmarshal[tpm20.TPMTSignature](csrResponse.IdevidSignatureCsr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal IDevID CSR signature: %w", err)
	}

	err = deps.VerifyTPMTSignature(csrResponse.CsrContents, idevidCsrSignature, &idevidCsrContents.IDevIDPub)
	if err != nil {
		return nil, fmt.Errorf("failed to verify IDevID CSR signature using IDevID public key: %w", err)
	}

	// TODO: do validation on EK obtained from the CSR.
	if fetchEKResp == nil {
		return nil, fmt.Errorf("%w: fetchEKResp cannot be nil", ErrInvalidRequest)
	}

	if idevidCsrContents.ProdSerial != controlCardID.ControlCardSerial {
		return nil, fmt.Errorf("%w: CSR serial (%s) does not match control card serial (%s)", ErrSerialMismatch, idevidCsrContents.ProdSerial, controlCardID.ControlCardSerial)
	}

	return &idevidCsrContents.IDevIDPub, nil
}
