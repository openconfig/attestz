#!/bin/bash
set -euo pipefail

BASE=$(bazel info bazel-genfiles)
ATTESTZ_NS='github.com/openconfig/attestz'

copy_generated() {
  pkg="$1"
  # Default to using package name for proto if $4 is unset
  proto="$1" && [ "${4++}" ] && proto="$4"
  # Bazel go_rules will create empty files containing "// +build ignore\n\npackage ignore"
  # in the case where the protoc compiler doesn't generate any output. See:
  # https://github.com/bazelbuild/rules_go/blob/03a8b8e90eebe699d7/go/tools/builders/protoc.go#L190
  for file in "${BASE}""/${3}""${proto}"_go_proto_/"${2}"/*.pb.go; do
    [[ $(head -n 1 "${file}") == "// +build ignore" ]] || cp -f "${file}" "${3}${pkg}/"
  done
}

bazel build //proto:all
# first arg is the package name, second arg is namespace for the package, and third is the location where the generated code will be saved.
copy_generated "tpm_enrollz"  ${ATTESTZ_NS}   "proto/"
copy_generated "tpm_attestz"  ${ATTESTZ_NS}   "proto/"
copy_generated "common_definitions"  ${ATTESTZ_NS}   "proto/"
