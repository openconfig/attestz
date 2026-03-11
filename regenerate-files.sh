#!/bin/bash
set -euo pipefail

BASE=$(bazel info bazel-genfiles)
ATTESTZ_NS='github.com/openconfig/attestz'

# Bazel go_rules will create empty files containing "// +build ignore\n\npackage ignore"
# in the case where the protoc compiler doesn't generate any output. See:
# https://github.com/bazelbuild/rules_go/blob/03a8b8e90eebe699d7/go/tools/builders/protoc.go#L190

bazel build //proto/attestz:all

# Clean up existing generated files in proto/attestz/
rm -f proto/attestz/*.pb.go

# Copy all generated files from the consolidated attestz_go_proto target
for file in "${BASE}/proto/attestz/attestz_go_proto_/github.com/openconfig/attestz/proto/attestz"/*.pb.go; do
  [[ $(head -n 1 "${file}") == "// +build ignore" ]] || cp -f "${file}" "proto/attestz/"
done
