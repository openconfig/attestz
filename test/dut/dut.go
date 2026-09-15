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

// Package dut is vendor-specific and should be implemented by each vendor.
// Each vendor only needs to cover their own switch chassis they want to test, and does not need to consider compatibility with other vendors.
package dut

import (
	"github.com/golang/glog"
)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Add any variables, data structures and helper functions in this file as needed to assist the functions below.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Target contains connection parameters for reaching the DUT's gNSI service.
type Target struct {
	Host string // Management IP or hostname of the switch chassis
	Port string // Port of the gNSI service on the switch (default: "9339")
}

// PrepareDUT prepares the switch chassis under test before enrollment.
//
// Implementation Guidance:
// Implement any logic here to prepare your switch chassis for Enrollz/Attestz testing.
// You can do one of the following:
//   - Use your organization's private libraries/CLIs to ensure gNSI is active and TPM 2.0 is initialized.
//   - Employ the Ondatra library (https://github.com/openconfig/ondatra) to interact with your switch chassis via a connected testbed.
//   - Leave as a no-op if your testbed switch is pre-configured and perpetually listening on its gNSI port.
func PrepareDUT() (*Target, error) {
	glog.Infof("=============================================================================")
	glog.Infof("Preparing the DUT for Enrollz TPM 2.0 testing")
	glog.Infof("=============================================================================")

	// Replace with your switch's management IP or hostname.
	return &Target{
		Host: "127.0.0.1",
		Port: "9339",
	}, nil
}
