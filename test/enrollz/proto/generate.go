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

// Package proto provides Enrollz SUT controller proto definitions.
package proto

//go:generate protoc -I. -I../../proto -Igithub.com/openconfig/attestz=../../.. --go_out=. --go_opt=paths=source_relative --go_opt=Mgithub.com/openconfig/attestz/proto/common_definitions.proto=github.com/openconfig/attestz/proto/common_definitions --go_opt=Mgoogle/rpc/status.proto=google.golang.org/genproto/googleapis/rpc/status --go-grpc_out=. --go-grpc_opt=paths=source_relative --go-grpc_opt=Mgoogle/rpc/status.proto=google.golang.org/genproto/googleapis/rpc/status sut.proto
