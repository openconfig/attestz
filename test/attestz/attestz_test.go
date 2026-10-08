//
// Copyright 2026 Google LLC
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
//

// Package attestz_test implements integration tests for the OpenConfig Attestz gNSI service.
//
// NOTE: The test cases in this file are not meant to all be executed together.
// Vendors should select and run the specific test case(s) matching their hardware
// configuration using the `-run` flag. Alternatively, they may delete or comment out
// any test cases that do not apply to their switch chassis before running `go test`.
//
// Additional test cases can be added to this file (or in separate *_test.go files)
// as needed depending on test requirements. Each test case can directly use the
// package-level `dutTarget` for device connection details and `attestzSUTClient`
// to invoke attestation through the SUT controller.
package attestz_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	ocdpb "github.com/openconfig/attestz/proto/common_definitions"
	sutpb "github.com/openconfig/attestz/test/attestz/proto"
)

// TestAttestz_InitialAttestation_TPM20_IDevID_SingleControlCard tests the remote attestation
// workflow using TPM 2.0 for switches with a single control card.
func TestAttestz_InitialAttestation_TPM20_IDevID_SingleControlCard(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	req := &sutpb.AttestDeviceRequest{
		Host:             dutTarget.Host,
		Port:             dutTarget.Port,
		ControlCardRoles: []ocdpb.ControlCardRole{ocdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE},
		HashAlgo:         ocdpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
	}

	resp, err := attestzSUTClient.AttestDevice(ctx, req)
	if err != nil {
		t.Fatalf("AttestDevice(%+v) failed: %v", req, err)
	}

	if len(resp.GetCardResults()) != 1 {
		t.Fatalf("AttestDevice returned %d card results, want 1", len(resp.GetCardResults()))
	}

	card := resp.GetCardResults()[0]
	if card.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("Attestation for card %v failed: [%v] %s",
			card.GetControlCardRole(),
			codes.Code(card.GetStatus().GetCode()),
			card.GetStatus().GetMessage(),
		)
	}
}

// TestAttestz_InitialAttestation_TPM20_IDevID_MultipleControlCards tests the remote attestation
// workflow using TPM 2.0 for switches with dual/redundant control cards.
func TestAttestz_InitialAttestation_TPM20_IDevID_MultipleControlCards(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	roles := []ocdpb.ControlCardRole{
		ocdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ocdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
	}

	req := &sutpb.AttestDeviceRequest{
		Host:             dutTarget.Host,
		Port:             dutTarget.Port,
		ControlCardRoles: roles,
		HashAlgo:         ocdpb.Tpm20HashAlgo_TPM_2_0_HASH_ALGO_SHA384,
	}

	resp, err := attestzSUTClient.AttestDevice(ctx, req)
	if err != nil {
		t.Fatalf("AttestDevice(%+v) failed: %v", req, err)
	}

	if len(resp.GetCardResults()) != len(roles) {
		t.Fatalf("AttestDevice returned %d card results, want %d", len(resp.GetCardResults()), len(roles))
	}

	for _, card := range resp.GetCardResults() {
		if card.GetStatus().GetCode() != int32(codes.OK) {
			t.Fatalf("Attestz attestation for control card %v failed: [%v] %s",
				card.GetControlCardRole(),
				codes.Code(card.GetStatus().GetCode()),
				card.GetStatus().GetMessage(),
			)
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add any additional test cases in this file as needed to cover specific switch workflows, PCR bank variations, or negative tests.
// e.g., TestAttestz_Negative_PCRMismatch, TestAttestz_Negative_UntrustedRootCA, etc.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
