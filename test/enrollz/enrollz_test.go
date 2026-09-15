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

// Package enrollz_test implements integration tests for the OpenConfig Enrollz gNSI service.
//
// Additional test cases can be added to this file (or in separate *_test.go files)
// as needed depending on test requirements. Each test case can directly use the
// package-level `dutTarget` for device connection details and `enrollzSUTClient`
// to invoke enrollment through the SUT controller.
package enrollz_test

import (
	"context"
	"testing"
	"time"

	ocdpb "github.com/openconfig/attestz/proto/common_definitions"
	sutpb "github.com/openconfig/attestz/test/enrollz/proto"
)

func TestEnrollz_InitialEnrollment_TPM20_IDevID_SingleControlCard(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	req := &sutpb.EnrollDeviceRequest{
		IpAddress:       dutTarget.IP,
		Port:            dutTarget.Port,
		ControlCardRole: ocdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		SslProfileId:    "tls",
	}

	resp, err := enrollzSUTClient.EnrollDevice(ctx, req)
	if err != nil {
		t.Fatalf("EnrollDevice(%+v) failed: %v", req, err)
	}

	if resp.GetStatus() != sutpb.EnrollDeviceResponse_STATUS_SUCCESS {
		t.Fatalf("Enrollz enrollment failed with status: %v without error", resp.GetStatus())
	}

	t.Logf("Enrollz enrollment succeeded")
}

func TestEnrollz_InitialEnrollment_TPM20_IDevID_MultipleControlCards(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	roles := []ocdpb.ControlCardRole{
		ocdpb.ControlCardRole_CONTROL_CARD_ROLE_ACTIVE,
		ocdpb.ControlCardRole_CONTROL_CARD_ROLE_STANDBY,
	}

	for _, role := range roles {
		req := &sutpb.EnrollDeviceRequest{
			IpAddress:       dutTarget.IP,
			Port:            dutTarget.Port,
			ControlCardRole: role,
			SslProfileId:    "tls",
		}

		resp, err := enrollzSUTClient.EnrollDevice(ctx, req)
		if err != nil {
			t.Fatalf("EnrollDevice(%+v) failed: %v", req, err)
		}
		if resp.GetStatus() != sutpb.EnrollDeviceResponse_STATUS_SUCCESS {
			t.Fatalf("Enrollz enrollment for control card %v failed with status: %v without error", req.GetControlCardRole(), resp.GetStatus())
		}
		t.Logf("Enrollz enrollment succeeded for control card: %v", req.GetControlCardRole())
	}

	t.Logf("Enrollz enrollment succeeded")
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add any additional test cases in this file as needed to cover specific switch workflows, rotation scenarios, or negative tests.
// e.g., TestEnrollz_CertificateRenewal, TestEnrollz_Negative_UntrustedRootCA, etc.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
