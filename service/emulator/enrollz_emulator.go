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

package main

import (
	"flag"

	log "github.com/golang/glog"
)

func main() {
	flag.Parse()

	log.Info("Initializing Enrollz Service!")

	// Build all infra-specific clients to communicate with the switch owner
	// dependency services and wire them to enrollz service biz logic library.
	//
	// For simplicity do this in main() for now - later we can add gRPC layer
	// and do this inside an RPC handler.

	// 1. Build an enrollz client to communicate with the device.

	// 2. Build a client to fetch switch vendor CA trust bundle.

	// 3. Build a client to communicate with the switch owner CA.

	// 4. Call enrollz biz logic module `EnrollControlCard()` for active and
	// standby control cards
}
