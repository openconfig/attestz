# Enrollz and Attestz Device/Server Business Logic

Infra-agnostic business logic of `enrollz` and `attestz` gRPC servers
that are hosted by the networking devices. One can import these libraries,
wire infra-specific service dependencies and add gRPC server layering
around them to build fully functional services (see
`//device/emulator:enrollz` and `//device/emulator:attestz` for an example).
Thus, these libraries can be shared by the switch vendors, used in e2e
regression tests relying on virtualized hardware or simply serve as a
reference implementation.
