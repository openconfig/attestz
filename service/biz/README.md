# Enrollz and Attestz *(Switch Owner)* Services Business Logic

Infra-agnostic business logic of Enrollz and Attestz Services (hosted by
the switch owner infra). One can import these libraries, wire infra-specific
service dependencies and add gRPC server layering around them to build fully
functional services (see `//service/emulator:enrollz` and
`//service/emulator:attestz` for an example). Thus, these libraries can be
shared by the switch owners, used in e2e regression tests relying on
virtualized hardware or simply serve as a reference implementation.

## Building

``` bash
## Verified to work with bazel of version 7.0.1
bazel build //service/biz:*
```
