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
	"crypto/x509"
	"fmt"

	log "github.com/golang/glog"

	cpb "github.com/openconfig/attestz/proto/common_definitions"
	epb "github.com/openconfig/attestz/proto/tpm_enrollz"

	"google.golang.org/protobuf/encoding/prototext"
)

// IssueOwnerIakCertReq is the request to SwitchOwnerCaClient.IssueOwnerIakCert().
type IssueOwnerIakCertReq struct {
	// Identity fields of a given switch control card.
	cardID *cpb.ControlCardVendorId
	// PEM-encoded IAK public key.
	iakPubPem string
}

// IssueOwnerIakCertResp is the response to SwitchOwnerCaClient.IssueOwnerIakCert().
type IssueOwnerIakCertResp struct {
	// PEM-encoded owner IAK cert (signed by the switch owner CA).
	ownerIakCertPem string
}

// IssueOwnerIDevIDCertReq is the request to SwitchOwnerCaClient.IssueOwnerIDevIDCert().
type IssueOwnerIDevIDCertReq struct {
	// Identity fields of a given switch control card.
	cardID *cpb.ControlCardVendorId
	// PEM-encoded IDevID public key.
	iDevIDPubPem string
}

// IssueOwnerIDevIDCertResp is the response to SwitchOwnerCaClient.IssueOwnerIDevIDCert().
type IssueOwnerIDevIDCertResp struct {
	// PEM-encoded owner IDevID cert (signed by the switch owner CA).
	ownerIDevIDCertPem string
}

// Client to communicate with the Switch Owner CA to issue oIAK and oIDevID certs.
type SwitchOwnerCaClient interface {
	// For a given switch control card ID, issue an oIAK PEM cert based on IAK public key PEM.
	IssueOwnerIakCert(req *IssueOwnerIakCertReq) (*IssueOwnerIakCertResp, error)

	// For a given switch control card ID, issue an oIDevID PEM cert based on IDevID public key PEM.
	IssueOwnerIDevIDCert(req *IssueOwnerIDevIDCertReq) (*IssueOwnerIDevIDCertResp, error)
}

// EnrollzDeviceClient is a wrapper around gRPC `TpmEnrollzServiceClient` to allow callers to specify
// `context.Context` and `grpc.CallOption`s.
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
	GetIakCert(req *epb.GetIakCertRequest) (*epb.GetIakCertResponse, error)

	// Returns `TpmEnrollzServiceClient.RotateOIakCert()` response.
	RotateOIakCert(req *epb.RotateOIakCertRequest) (*epb.RotateOIakCertResponse, error)
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

// EnrollControlCardReq is the request to EnrollControlCard().
type EnrollControlCardReq struct {
	// Selection of a specific switch control card.
	controlCardSelection *cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	deps EnrollzInfraDeps
	// Verification options for IAK and IDevID certs.
	certVerificationOpts x509.VerifyOptions
}

// EnrollControlCard is a "client"/switch-owner side implementation of Enrollz service. This client-side logic
// is part of the switch owner infra/service and is expected to communicate with a device/switch (hosting
// enrollz gRPC endpoints) to verify its TPM-based identity and provision it with the switch-owner-issued,
// TPM-based attestation and TLS certs: Owner IAK and Owner IDevID certs, respectively. Switch owner is
// expected to TPM-enroll one switch control card at a time, starting with an active card.
//
// More specifically, this function targets initial install/enrollment of the device. This means that the
// switch is expected to rely on the IDevID cert for establishing a secure TLS connection. Consumers
// of this function should carefully choose CA trust anchors in `x509.VerifyOptions` to include switch
// vendor CA root and intermediate certs that signed both IAK and IDevID certs. By the end of the workflow
// a given control card will obtain its first set of Owner IAK and Owner IDevID certs (signed by the switch
// owner CA).
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
	tpmCertVerifierReq := &VerifyIakAndIDevIDCertsReq{
		controlCardID:        getIakCertResp.ControlCardId,
		iakCertPem:           getIakCertResp.IakCert,
		iDevIDCertPem:        getIakCertResp.IdevidCert,
		certVerificationOpts: req.certVerificationOpts,
	}
	tpmCertVerifierResp, err := req.deps.VerifyIakAndIDevIDCerts(tpmCertVerifierReq)
	if err != nil {
		return fmt.Errorf("failed to verify IAK_cert_pem=%s and IDevID_cert_pem=%s: %w",
			tpmCertVerifierReq.iakCertPem, tpmCertVerifierReq.iDevIDCertPem, err)
	}
	log.Infof("Successfully verified IAK and IDevID certs and parsed IAK_pub_pem=%s and IDevID_pub_pem=%s",
		tpmCertVerifierResp.iakPubPem, tpmCertVerifierResp.iDevIDPubPem)

	// 3. Call Switch Owner CA to issue oIAK and oIDevID certs.
	issueOwnerIakCertReq := &IssueOwnerIakCertReq{
		cardID:    getIakCertResp.ControlCardId,
		iakPubPem: tpmCertVerifierResp.iakPubPem,
	}
	issueOwnerIakCertResp, err := req.deps.IssueOwnerIakCert(issueOwnerIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to execute Switch Owner CA IssueOwnerIakCert() with control_card_id=%s IAK_pub_pem=%s: %w",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iakPubPem, err)
	}
	log.Infof("Successfully received Switch Owner CA IssueOwnerIakCert() resp=%s for control_card_id=%s IAK_pub_pem=%s",
		issueOwnerIakCertResp.ownerIakCertPem, prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iakPubPem)

	issueOwnerIDevIDCertReq := &IssueOwnerIDevIDCertReq{
		cardID:       getIakCertResp.ControlCardId,
		iDevIDPubPem: tpmCertVerifierResp.iDevIDPubPem,
	}
	issueOwnerIDevIDCertResp, err := req.deps.IssueOwnerIDevIDCert(issueOwnerIDevIDCertReq)

	if err != nil {
		return fmt.Errorf("failed to execute Switch Owner CA IssueOwnerIDevIDCert() with control_card_id=%s IDevID_pub_pem=%s: %w",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iDevIDPubPem, err)
	}
	log.Infof("Successfully received Switch Owner CA IssueOwnerIDevIDCert() resp=%s for control_card_id=%s IDevID_pub_pem=%s",
		issueOwnerIDevIDCertResp.ownerIDevIDCertPem, prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.iDevIDPubPem)

	// 4. Call device's RotateOIakCert for the specified card card to persist oIAK and oIDevID certs.
	rotateOIakCertReq := &epb.RotateOIakCertRequest{
		ControlCardSelection: req.controlCardSelection,
		OiakCert:             issueOwnerIakCertResp.ownerIakCertPem,
		OidevidCert:          issueOwnerIDevIDCertResp.ownerIDevIDCertPem,
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

// RotateOwnerIakCertReq is the request to RotateOwnerIakCert().
type RotateOwnerIakCertReq struct {
	// Selection of a specific switch control card.
	controlCardSelection *cpb.ControlCardSelection
	// Infra-specific wired dependencies.
	deps EnrollzInfraDeps
	// Verification options for IAK cert.
	certVerificationOpts x509.VerifyOptions
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
func RotateOwnerIakCert(req *RotateOwnerIakCertReq) error {
	// 1. Call device's GetIakCert API for the specified control card.
	getIakCertReq := &epb.GetIakCertRequest{ControlCardSelection: req.controlCardSelection}
	getIakCertResp, err := req.deps.GetIakCert(getIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to retrieve IAK cert from the device with req=%s: %w",
			prototext.Format(getIakCertReq), err)
	}
	log.Infof("Successfully received from device GetIakCert() resp=%s for req=%s",
		prototext.Format(getIakCertResp), prototext.Format(getIakCertReq))

	// 2. Validate and parse IAK cert.
	tpmCertVerifierReq := &VerifyTpmCertReq{
		controlCardID:        getIakCertResp.ControlCardId,
		certPem:              getIakCertResp.IakCert,
		certVerificationOpts: req.certVerificationOpts,
	}
	tpmCertVerifierResp, err := req.deps.VerifyTpmCert(tpmCertVerifierReq)
	if err != nil {
		return fmt.Errorf("failed to verify IAK_cert_pem=%s: %w",
			tpmCertVerifierReq.certPem, err)
	}
	log.Infof("Successfully verified IAK cert and parsed IAK_pub_pem=%s",
		tpmCertVerifierResp.pubPem)

	// 3. Call Switch Owner CA to issue a new oIAK cert.
	issueOwnerIakCertReq := &IssueOwnerIakCertReq{
		cardID:    getIakCertResp.ControlCardId,
		iakPubPem: tpmCertVerifierResp.pubPem,
	}
	issueOwnerIakCertResp, err := req.deps.IssueOwnerIakCert(issueOwnerIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to execute Switch Owner CA IssueOwnerIakCert() with control_card_id=%s IAK_pub_pem=%s: %w",
			prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.pubPem, err)
	}
	log.Infof("Successfully received Switch Owner CA IssueOwnerIakCert() resp=%s for control_card_id=%s IAK_pub_pem=%s",
		issueOwnerIakCertResp.ownerIakCertPem, prototext.Format(getIakCertResp.ControlCardId), tpmCertVerifierResp.pubPem)

	// 4. Call device's RotateOIakCert for the specified card to persist a new (rotate an existing) oIAK cert.
	rotateOIakCertReq := &epb.RotateOIakCertRequest{
		ControlCardSelection: req.controlCardSelection,
		OiakCert:             issueOwnerIakCertResp.ownerIakCertPem,
	}
	rotateOIakCertResp, err := req.deps.RotateOIakCert(rotateOIakCertReq)
	if err != nil {
		return fmt.Errorf("failed to rotate oIAK cert from the device with req=%s: %w",
			prototext.Format(rotateOIakCertReq), err)
	}
	log.Infof("Successfully received from device RotateOIakCert() resp=%s for req=%s",
		prototext.Format(rotateOIakCertResp), prototext.Format(rotateOIakCertReq))

	// Return a successful (no-error) response.
	return nil
}
