# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Note: Build this Dockerfile from the repository root:
# docker build -t openconfig/attestz-sut:latest -f test/attestz/sut/controller/deploy/Dockerfile .

FROM golang:1.26 AS builder

WORKDIR /workspace

# Copy module files and dependencies
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source packages
COPY proto/ proto/
COPY service/ service/
COPY test/enrollz/caservice/ test/enrollz/caservice/
COPY test/attestz/proto/ test/attestz/proto/
COPY test/attestz/pcrprovider/ test/attestz/pcrprovider/
COPY test/attestz/tpmutil/ test/attestz/tpmutil/
COPY test/attestz/sut/controller/ test/attestz/sut/controller/

# Build the SUT binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /attestz-sut ./test/attestz/sut/controller/

# checkov:skip=CKV_DOCKER_2: Distroless image has no shell for Docker HEALTHCHECK
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder /attestz-sut ./attestz-sut

# Bake in CA certificates if provided under caservice/certs/
COPY test/enrollz/caservice/certs/ ./certs/

USER nonroot
EXPOSE 9999/tcp

ENTRYPOINT ["/app/attestz-sut"]
CMD ["--logtostderr", "--controller_port=9999"]