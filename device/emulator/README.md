# Enrollz and Attestz Device/Server Emulation

The code located in this directory is intended to emulate typical `enrollz`
and `attestz` gRPC servers that are hosted by the networking devices. Switch
owners are expected to implement Enrollz and Attestz Services that would
communicate to these switch-hosted gRPC endpoints to drive TPM 2.0 enrollment
and attestation workflows.
