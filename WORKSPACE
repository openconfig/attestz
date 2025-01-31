# Copyright 2024 Google LLC
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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_proto_grpc",
    sha256 = "c0d718f4d892c524025504e67a5bfe83360b3a982e654bc71fed7514eb8ac8ad",
    strip_prefix = "rules_proto_grpc-4.6.0",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/4.6.0.tar.gz"],
)

# googleapis has not had a release since 2016 - take the master version as of 31-jan-25
http_archive(
    name = "com_google_googleapis",
    sha256 = "79919526bf4a5f65d698bf07ef392c8f2bf3e8bce84217849cf53a8d3ea83b77",
    strip_prefix = "googleapis-dd1210af5bee414c9e606f5637e0eb0fd9d894e8",
    urls = ["https://github.com/googleapis/googleapis/archive/dd1210af5bee414c9e606f5637e0eb0fd9d894e8.tar.gz"],
)

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")
switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
    go = True,
)

load(
    "@rules_proto_grpc//:repositories.bzl",
    "bazel_gazelle",
    "io_bazel_rules_go",
    "rules_proto_grpc_repos",
    "rules_proto_grpc_toolchains",
)

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

### Golang
io_bazel_rules_go()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(go_version = "1.20")

# gazelle:repo bazel_gazelle
bazel_gazelle()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

local_repository(
    name = "local_repo_root",
    path = "./",
)

load("@rules_proto_grpc//go:repositories.bzl", rules_proto_grpc_go_repos = "go_repos")
load("//:deps.bzl", "go_dependencies")

go_dependencies()

rules_proto_grpc_go_repos()

# Load gazelle_dependencies last, so that the newer version of org_golang_google_grpc is used.
# see https://github.com/rules-proto-grpc/rules_proto_grpc/issues/160
gazelle_dependencies()

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()
