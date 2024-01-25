// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.10
// source: github.com/openconfig/attestz/proto/tpm_enrollz.proto

package attestz

import (
	context "context"
	common_definitions "github.com/openconfig/attestz/proto/common_definitions"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetIakCertRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,1,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
}

func (x *GetIakCertRequest) Reset() {
	*x = GetIakCertRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetIakCertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIakCertRequest) ProtoMessage() {}

func (x *GetIakCertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIakCertRequest.ProtoReflect.Descriptor instead.
func (*GetIakCertRequest) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{0}
}

func (x *GetIakCertRequest) GetControlCardSelection() *common_definitions.ControlCardSelection {
	if x != nil {
		return x.ControlCardSelection
	}
	return nil
}

type GetIakCertResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControlCardId *common_definitions.ControlCardVendorId `protobuf:"bytes,1,opt,name=control_card_id,json=controlCardId,proto3" json:"control_card_id,omitempty"`
	IakCert       string                                  `protobuf:"bytes,2,opt,name=iak_cert,json=iakCert,proto3" json:"iak_cert,omitempty"`
	IdevidCert    string                                  `protobuf:"bytes,3,opt,name=idevid_cert,json=idevidCert,proto3" json:"idevid_cert,omitempty"`
}

func (x *GetIakCertResponse) Reset() {
	*x = GetIakCertResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetIakCertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIakCertResponse) ProtoMessage() {}

func (x *GetIakCertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIakCertResponse.ProtoReflect.Descriptor instead.
func (*GetIakCertResponse) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{1}
}

func (x *GetIakCertResponse) GetControlCardId() *common_definitions.ControlCardVendorId {
	if x != nil {
		return x.ControlCardId
	}
	return nil
}

func (x *GetIakCertResponse) GetIakCert() string {
	if x != nil {
		return x.IakCert
	}
	return ""
}

func (x *GetIakCertResponse) GetIdevidCert() string {
	if x != nil {
		return x.IdevidCert
	}
	return ""
}

type RotateOIakCertRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,1,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
	OiakCert             string                                   `protobuf:"bytes,2,opt,name=oiak_cert,json=oiakCert,proto3" json:"oiak_cert,omitempty"`
	OidevidCert          string                                   `protobuf:"bytes,3,opt,name=oidevid_cert,json=oidevidCert,proto3" json:"oidevid_cert,omitempty"`
}

func (x *RotateOIakCertRequest) Reset() {
	*x = RotateOIakCertRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RotateOIakCertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateOIakCertRequest) ProtoMessage() {}

func (x *RotateOIakCertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotateOIakCertRequest.ProtoReflect.Descriptor instead.
func (*RotateOIakCertRequest) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{2}
}

func (x *RotateOIakCertRequest) GetControlCardSelection() *common_definitions.ControlCardSelection {
	if x != nil {
		return x.ControlCardSelection
	}
	return nil
}

func (x *RotateOIakCertRequest) GetOiakCert() string {
	if x != nil {
		return x.OiakCert
	}
	return ""
}

func (x *RotateOIakCertRequest) GetOidevidCert() string {
	if x != nil {
		return x.OidevidCert
	}
	return ""
}

type RotateOIakCertResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RotateOIakCertResponse) Reset() {
	*x = RotateOIakCertResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RotateOIakCertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateOIakCertResponse) ProtoMessage() {}

func (x *RotateOIakCertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotateOIakCertResponse.ProtoReflect.Descriptor instead.
func (*RotateOIakCertResponse) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{3}
}

var File_github_com_openconfig_attestz_proto_tpm_enrollz_proto protoreflect.FileDescriptor

var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDesc = []byte{
	0x0a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65,
	0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x70, 0x6d, 0x5f, 0x65, 0x6e, 0x72, 0x6f, 0x6c, 0x6c,
	0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x1a, 0x3c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x73, 0x0a, 0x11, 0x47, 0x65, 0x74,
	0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x5e,
	0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x73,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x14, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0xa1,
	0x01, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4f, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27,
	0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x56,
	0x65, 0x6e, 0x64, 0x6f, 0x72, 0x49, 0x64, 0x52, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x43, 0x61, 0x72, 0x64, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x69, 0x61, 0x6b, 0x5f, 0x63, 0x65,
	0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x69, 0x61, 0x6b, 0x43, 0x65, 0x72,
	0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x43, 0x65,
	0x72, 0x74, 0x22, 0xb7, 0x01, 0x0a, 0x15, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x4f, 0x49, 0x61,
	0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x5e, 0x0a, 0x16,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x73, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x6f,
	0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x14, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43,
	0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09,
	0x6f, 0x69, 0x61, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x6f, 0x69, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x69, 0x64,
	0x65, 0x76, 0x69, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x6f, 0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x43, 0x65, 0x72, 0x74, 0x22, 0x18, 0x0a, 0x16,
	0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x4f, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xd9, 0x01, 0x0a, 0x11, 0x54, 0x70, 0x6d, 0x45, 0x6e,
	0x72, 0x6f, 0x6c, 0x6c, 0x7a, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5b, 0x0a, 0x0a,
	0x47, 0x65, 0x74, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x25, 0x2e, 0x6f, 0x70, 0x65,
	0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e,
	0x47, 0x65, 0x74, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x26, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x47, 0x65, 0x74, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x67, 0x0a, 0x0e, 0x52, 0x6f, 0x74,
	0x61, 0x74, 0x65, 0x4f, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x29, 0x2e, 0x6f, 0x70,
	0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a,
	0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x4f, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x52, 0x6f, 0x74, 0x61,
	0x74, 0x65, 0x4f, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x42, 0x1f, 0x5a, 0x1d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x7a, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescOnce sync.Once
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescData = file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDesc
)

func file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP() []byte {
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescOnce.Do(func() {
		file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescData)
	})
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescData
}

var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_goTypes = []interface{}{
	(*GetIakCertRequest)(nil),                       // 0: openconfig.attestz.GetIakCertRequest
	(*GetIakCertResponse)(nil),                      // 1: openconfig.attestz.GetIakCertResponse
	(*RotateOIakCertRequest)(nil),                   // 2: openconfig.attestz.RotateOIakCertRequest
	(*RotateOIakCertResponse)(nil),                  // 3: openconfig.attestz.RotateOIakCertResponse
	(*common_definitions.ControlCardSelection)(nil), // 4: openconfig.attestz.ControlCardSelection
	(*common_definitions.ControlCardVendorId)(nil),  // 5: openconfig.attestz.ControlCardVendorId
}
var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_depIdxs = []int32{
	4, // 0: openconfig.attestz.GetIakCertRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	5, // 1: openconfig.attestz.GetIakCertResponse.control_card_id:type_name -> openconfig.attestz.ControlCardVendorId
	4, // 2: openconfig.attestz.RotateOIakCertRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	0, // 3: openconfig.attestz.TpmEnrollzService.GetIakCert:input_type -> openconfig.attestz.GetIakCertRequest
	2, // 4: openconfig.attestz.TpmEnrollzService.RotateOIakCert:input_type -> openconfig.attestz.RotateOIakCertRequest
	1, // 5: openconfig.attestz.TpmEnrollzService.GetIakCert:output_type -> openconfig.attestz.GetIakCertResponse
	3, // 6: openconfig.attestz.TpmEnrollzService.RotateOIakCert:output_type -> openconfig.attestz.RotateOIakCertResponse
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_init() }
func file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_init() {
	if File_github_com_openconfig_attestz_proto_tpm_enrollz_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetIakCertRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetIakCertResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RotateOIakCertRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RotateOIakCertResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_goTypes,
		DependencyIndexes: file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_depIdxs,
		MessageInfos:      file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes,
	}.Build()
	File_github_com_openconfig_attestz_proto_tpm_enrollz_proto = out.File
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDesc = nil
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_goTypes = nil
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TpmEnrollzServiceClient is the client API for TpmEnrollzService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TpmEnrollzServiceClient interface {
	GetIakCert(ctx context.Context, in *GetIakCertRequest, opts ...grpc.CallOption) (*GetIakCertResponse, error)
	RotateOIakCert(ctx context.Context, in *RotateOIakCertRequest, opts ...grpc.CallOption) (*RotateOIakCertResponse, error)
}

type tpmEnrollzServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTpmEnrollzServiceClient(cc grpc.ClientConnInterface) TpmEnrollzServiceClient {
	return &tpmEnrollzServiceClient{cc}
}

func (c *tpmEnrollzServiceClient) GetIakCert(ctx context.Context, in *GetIakCertRequest, opts ...grpc.CallOption) (*GetIakCertResponse, error) {
	out := new(GetIakCertResponse)
	err := c.cc.Invoke(ctx, "/openconfig.attestz.TpmEnrollzService/GetIakCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tpmEnrollzServiceClient) RotateOIakCert(ctx context.Context, in *RotateOIakCertRequest, opts ...grpc.CallOption) (*RotateOIakCertResponse, error) {
	out := new(RotateOIakCertResponse)
	err := c.cc.Invoke(ctx, "/openconfig.attestz.TpmEnrollzService/RotateOIakCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TpmEnrollzServiceServer is the server API for TpmEnrollzService service.
type TpmEnrollzServiceServer interface {
	GetIakCert(context.Context, *GetIakCertRequest) (*GetIakCertResponse, error)
	RotateOIakCert(context.Context, *RotateOIakCertRequest) (*RotateOIakCertResponse, error)
}

// UnimplementedTpmEnrollzServiceServer can be embedded to have forward compatible implementations.
type UnimplementedTpmEnrollzServiceServer struct {
}

func (*UnimplementedTpmEnrollzServiceServer) GetIakCert(context.Context, *GetIakCertRequest) (*GetIakCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetIakCert not implemented")
}
func (*UnimplementedTpmEnrollzServiceServer) RotateOIakCert(context.Context, *RotateOIakCertRequest) (*RotateOIakCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RotateOIakCert not implemented")
}

func RegisterTpmEnrollzServiceServer(s *grpc.Server, srv TpmEnrollzServiceServer) {
	s.RegisterService(&_TpmEnrollzService_serviceDesc, srv)
}

func _TpmEnrollzService_GetIakCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetIakCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TpmEnrollzServiceServer).GetIakCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openconfig.attestz.TpmEnrollzService/GetIakCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TpmEnrollzServiceServer).GetIakCert(ctx, req.(*GetIakCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TpmEnrollzService_RotateOIakCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RotateOIakCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TpmEnrollzServiceServer).RotateOIakCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/openconfig.attestz.TpmEnrollzService/RotateOIakCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TpmEnrollzServiceServer).RotateOIakCert(ctx, req.(*RotateOIakCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TpmEnrollzService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "openconfig.attestz.TpmEnrollzService",
	HandlerType: (*TpmEnrollzServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetIakCert",
			Handler:    _TpmEnrollzService_GetIakCert_Handler,
		},
		{
			MethodName: "RotateOIakCert",
			Handler:    _TpmEnrollzService_RotateOIakCert_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "github.com/openconfig/attestz/proto/tpm_enrollz.proto",
}