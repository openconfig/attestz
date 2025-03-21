// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.10
// source: github.com/openconfig/attestz/proto/tpm_attestz.proto

package attestz

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// TpmAttestzServiceClient is the client API for TpmAttestzService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TpmAttestzServiceClient interface {
	Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error)
}

type tpmAttestzServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTpmAttestzServiceClient(cc grpc.ClientConnInterface) TpmAttestzServiceClient {
	return &tpmAttestzServiceClient{cc}
}

func (c *tpmAttestzServiceClient) Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error) {
	out := new(AttestResponse)
	err := c.cc.Invoke(ctx, "/openconfig.attestz.TpmAttestzService/Attest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TpmAttestzServiceServer is the server API for TpmAttestzService service.
// All implementations must embed UnimplementedTpmAttestzServiceServer
// for forward compatibility
type TpmAttestzServiceServer interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	mustEmbedUnimplementedTpmAttestzServiceServer()
}

// UnimplementedTpmAttestzServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTpmAttestzServiceServer struct {
}

func (UnimplementedTpmAttestzServiceServer) Attest(context.Context, *AttestRequest) (*AttestResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Attest not implemented")
}
func (UnimplementedTpmAttestzServiceServer) mustEmbedUnimplementedTpmAttestzServiceServer() {}

// UnsafeTpmAttestzServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TpmAttestzServiceServer will
// result in compilation errors.
type UnsafeTpmAttestzServiceServer interface {
	mustEmbedUnimplementedTpmAttestzServiceServer()
}

func RegisterTpmAttestzServiceServer(s grpc.ServiceRegistrar, srv TpmAttestzServiceServer) {
	s.RegisterService(&TpmAttestzService_ServiceDesc, srv)
}

func _TpmAttestzService_Attest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TpmAttestzServiceServer).Attest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openconfig.attestz.TpmAttestzService/Attest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TpmAttestzServiceServer).Attest(ctx, req.(*AttestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TpmAttestzService_ServiceDesc is the grpc.ServiceDesc for TpmAttestzService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TpmAttestzService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "openconfig.attestz.TpmAttestzService",
	HandlerType: (*TpmAttestzServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Attest",
			Handler:    _TpmAttestzService_Attest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/openconfig/attestz/proto/tpm_attestz.proto",
}
