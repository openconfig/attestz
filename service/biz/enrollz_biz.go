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
	log "github.com/golang/glog"
)

func EnrollDevice() {
	log.Error("Enrollz biz logic is not implemented yet!")
	// 1. Fetch Switch Vendor CA trust bundle.

	// 2. Call device's GetIakCert API for Active control card

	// 3. Validate IDevID TLS cert

	// 4. Validate IAK cert

	// 5. Make sure IAK and IDevID serials match

	// 6. Extract IAK pub from IAK cert and validate it (accepted crypto algo and key length)

	// 7. Extract IDevID pub from IDevID cert and validate it (accepted crypto algo and key length)

	// 8. Call Owner CA to issue oIAK and oIDevID certs

	// 9. Call device's RotateOIakCert for the device to persist oIAK and oIDevID certs

	// 10. Repeat steps 2-9 for Standby control card
}
