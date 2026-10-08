#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# Resolves to the repository root directory (openconfig/attestz) regardless of where the script is run from.
ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." &>/dev/null && pwd)

go build -o "${ROOT_DIR}/test/enrollz/sut/controller/main" "${ROOT_DIR}/test/enrollz/sut/controller"
"${ROOT_DIR}/test/enrollz/sut/controller/main" \
	--alsologtostderr \
	--vendor_ca_cert_path="${ROOT_DIR}/test/caservice/certs/vendorca.crt" \
	--owner_ca_cert_path="${ROOT_DIR}/test/caservice/certs/ownerca.crt" \
	--owner_ca_key_path="${ROOT_DIR}/test/caservice/certs/ownerca.key" \
	"$@"
