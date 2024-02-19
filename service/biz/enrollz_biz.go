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

// Infra-agnostic business logic of Enrollz Service hosted by the switch owner infra.
package biz

import (
	"crypto/x509"
	"fmt"

	log "github.com/golang/glog"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"

	"google.golang.org/protobuf/encoding/prototext"
)

// Client to communicate with the Switch Owner CA to issue oIAK and oIDevID certs.
type SwitchOwnerCaClient interface {
	// For a given switch control card ID, issue an oIAK PEM cert based on IAK public key PEM.
	IssueOwnerIakCert(cardId *cpb.ControlCardVendorId, iakPubPem string) (string, error)

	// For a given switch control card ID, issue an oIDevID PEM cert based on IDevID public key PEM.
	IssueOwnerIDevIdCert(cardId *cpb.ControlCardVendorId, iDevIdPubPem string) (string, error)
}

// Wrapper around gRPC `TpmEnrollzServiceClient` to allow callers to specify `context.Context`
// and `grpc.CallOption`s.
type EnrollzDeviceClient interface {
	// Returns `TpmEnrollzServiceClient.GetIakCert()` response.
	//
	// For an active control card IDevID cert *must* come from the TLS handshake. Even though the device may
	// optionally also specify active card's IDevID cert in the response payload, as part of this
	// EnrollzDeviceClient.GetIakCert() implementation it is expected that the caller will overwrite/set this
	// response payload idevid_cert field with the IDevID cert from the TLS handshake.
	//
	// As specified in https://github.com/openconfig/attestz README, it is impossible to talk directly to the
	// standby control card (so all calls to standby card are relayed by the active card), and it is a
	// responsibility of the active control card to authenticate standby card using IDevID handshake.
	// Thus, for standby card the best we can do in this case is fetch it's IDevID cert from the response
	// payload (as opposed to TLS handshake - what we do for an active card enrollment) which active card
	// is responsible to populate.
	GetIakCert(req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error)

	// Returns `TpmEnrollzServiceClient.RotateOIakCert()` response.
	RotateOIakCert(req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error)
}

// Infra-specific dependencies of this enrollz business logic lib. A service can create all these dependencies
// and wire them to the library on server start-up.
type EnrollzInfraDeps interface {
	// Client to communicate with Switch Owner CA to issue oIAK and oIDevID certs.
	SwitchOwnerCaClient

	// Client to communicate with the switch's enrollz endpoints.
	EnrollzDeviceClient

	// Parser and verifier of IAK and IDevID certs.
	TpmCertVerifier
}

// Request to EnrollControlCard().
type EnrollControlCardReq struct {
	// Selection of a specific switch control card.
	controlCardSelection *cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	deps EnrollzInfraDeps
	// Verification options for IAK and IDevID certs.
	certVerificationOpts x509.VerifyOptions
}

// This is a "client"/switch-owner side implementation of Enrollz service. This client-side logic
// is part of the switch owner infra/service and is expected to communicate with a device/switch (hosting
// enrollz gRPC endpoints) to verify its TPM-based identity and provision it with the switch-owner-issued,
// TPM-based attestation and TLS certs: Owner IAK and Owner IDevID certs respectively. Switch owner is
// expected to TPM-enroll one switch control card at a time, starting with an active card.
func EnrollControlCard(req *EnrollControlCardReq) error {
	// 1. Call device's GetIakCert API for the specified control card.
	getIakCertReq := &epb.GetIakCertRequest{ControlCardSelection: req.controlCardSelection}
	getIakCertResp, err := req.deps.GetIakCert(getIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to retrieve IAK cert from the device with req=%s: %w",
			prototext.Format(getIakCertReq), err)
	}
	log.Infof("Successfully received from device GetIakCert() resp=%s for req=%s",
		prototext.Format(getIakCertResp), prototext.Format(getIakCertReq))

	// 2. Validate and parse IDevID and IAK certs.
	tpmCertVerifierReq := &TpmCertVerifierReq{
		iakCertPem:           getIakCertResp.IakCert,
		iDevIdCertPem:        getIakCertResp.IdevidCert,
		certVerificationOpts: req.certVerificationOpts,
	}
	tpmCertVerifierResp, err := req.deps.VerifyAndParseIakAndIDevIdCerts(tpmCertVerifierReq)
	if err != nil {
		return fmt.Errorf("failed to verify IAK_cert_pem=%s and IDevID_cert_pem=%s: %w",
			tpmCertVerifierReq.iakCertPem, tpmCertVerifierReq.iDevIdCertPem, err)
	}
	log.Infof("Successfully verified IAK and IDevID certs and parsed IAK_pub_pem=%s and IDevID_pub_pem=%s",
		tpmCertVerifierResp.iakPubPem, tpmCertVerifierResp.iDevIdPubPem)

	// 3. Call Switch Owner CA to issue oIAK and oIDevID certs.
	oIakCertPem, err := req.deps.IssueOwnerIakCert(getIakCertResp.ControlCardId, tpmCertVerifierResp.iakPubPem)
	if err != nil {
		return fmt.Errorf("failed to execute Switch Owner CA IssueOwnerIakCert() with control_card_id=%s IAK_pub_pem=%s: %w",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iakPubPem, err)
	}
	log.Infof("Successfully received Switch Owner CA IssueOwnerIakCert() resp=%s for control_card_id=%s IAK_pub_pem=%s",
		oIakCertPem, prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iakPubPem)

	oIDevIdCertPem, err := req.deps.IssueOwnerIDevIdCert(getIakCertResp.ControlCardId, tpmCertVerifierResp.iDevIdPubPem)
	if err != nil {
		return fmt.Errorf("failed to execute Switch Owner CA IssueOwnerIDevIdCert() with control_card_id=%s IDevID_pub_pem=%s: %w",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iDevIdPubPem, err)
	}
	log.Infof("Successfully received Switch Owner CA IssueOwnerIDevIdCert() resp=%s for control_card_id=%s IDevID_pub_pem=%s",
		oIDevIdCertPem, prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iDevIdPubPem)

	// 4. Call device's RotateOIakCert for the specified card card to persist oIAK and oIDevID certs.
	rotateOIakCertReq := &epb.RotateOIakCertRequest{
		ControlCardSelection: req.controlCardSelection,
		OiakCert:             oIakCertPem,
		OidevidCert:          oIDevIdCertPem,
	}
	rotateOIakCertResp, err := req.deps.RotateOIakCert(rotateOIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to rotate oIAK and oIDevID certs from the device with req=%s: %w",
			prototext.Format(rotateOIakCertReq), err)
	}
	log.Infof("Successfully received from device RotateOIakCert() resp=%s for req=%s",
		prototext.Format(rotateOIakCertResp), prototext.Format(rotateOIakCertReq))

	// Return a successful (no-error) response.
	return nil
}
