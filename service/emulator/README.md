# Enrollz and Attestz *(Switch Owner)* Services Emulation

The code located in this directory is intended to emulate typical Enrollz
and Attestz Services hosted by a switch owner. These services will
communicate with the networking devices hosting gRPC `enrollz` and
`attestz` endpoints and drive TPM 2.0 enrollment and attestation workflows.

## Building

``` bash
## Verified to work with bazel of version 7.0.1
bazel build //service/emulator:*
```

## Running

``` bash
./bazel-bin/service/emulator/enrollz_emulator_/enrollz_emulator --alsologtostderr
```
