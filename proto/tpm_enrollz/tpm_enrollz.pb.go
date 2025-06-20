// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.2
// 	protoc        v5.29.3
// source: github.com/openconfig/attestz/proto/tpm_enrollz.proto

package attestz

import (
	common_definitions "github.com/openconfig/attestz/proto/common_definitions"
	tpm_attestz "github.com/openconfig/attestz/proto/tpm_attestz"
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
	state                protoimpl.MessageState                   `protogen:"open.v1"`
	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,1,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
	Nonce                []byte                                   `protobuf:"bytes,2,opt,name=nonce,proto3,oneof" json:"nonce,omitempty"`
	HashAlgo             *tpm_attestz.Tpm20HashAlgo               `protobuf:"varint,3,opt,name=hash_algo,json=hashAlgo,proto3,enum=openconfig.attestz.Tpm20HashAlgo,oneof" json:"hash_algo,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *GetIakCertRequest) Reset() {
	*x = GetIakCertRequest{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetIakCertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIakCertRequest) ProtoMessage() {}

func (x *GetIakCertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0]
	if x != nil {
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

func (x *GetIakCertRequest) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *GetIakCertRequest) GetHashAlgo() tpm_attestz.Tpm20HashAlgo {
	if x != nil && x.HashAlgo != nil {
		return *x.HashAlgo
	}
	return tpm_attestz.Tpm20HashAlgo(0)
}

type GetIakCertResponse struct {
	state          protoimpl.MessageState                  `protogen:"open.v1"`
	ControlCardId  *common_definitions.ControlCardVendorId `protobuf:"bytes,1,opt,name=control_card_id,json=controlCardId,proto3" json:"control_card_id,omitempty"`
	IakCert        string                                  `protobuf:"bytes,2,opt,name=iak_cert,json=iakCert,proto3" json:"iak_cert,omitempty"`
	IdevidCert     string                                  `protobuf:"bytes,3,opt,name=idevid_cert,json=idevidCert,proto3" json:"idevid_cert,omitempty"`
	NonceSignature []byte                                  `protobuf:"bytes,4,opt,name=nonce_signature,json=nonceSignature,proto3,oneof" json:"nonce_signature,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *GetIakCertResponse) Reset() {
	*x = GetIakCertResponse{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetIakCertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIakCertResponse) ProtoMessage() {}

func (x *GetIakCertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1]
	if x != nil {
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

func (x *GetIakCertResponse) GetNonceSignature() []byte {
	if x != nil {
		return x.NonceSignature
	}
	return nil
}

type RotateOIakCertRequest struct {
	state                protoimpl.MessageState                   `protogen:"open.v1"`
	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,1,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
	OiakCert             string                                   `protobuf:"bytes,2,opt,name=oiak_cert,json=oiakCert,proto3" json:"oiak_cert,omitempty"`
	OidevidCert          string                                   `protobuf:"bytes,3,opt,name=oidevid_cert,json=oidevidCert,proto3" json:"oidevid_cert,omitempty"`
	SslProfileId         string                                   `protobuf:"bytes,4,opt,name=ssl_profile_id,json=sslProfileId,proto3" json:"ssl_profile_id,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *RotateOIakCertRequest) Reset() {
	*x = RotateOIakCertRequest{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotateOIakCertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateOIakCertRequest) ProtoMessage() {}

func (x *RotateOIakCertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[2]
	if x != nil {
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

func (x *RotateOIakCertRequest) GetSslProfileId() string {
	if x != nil {
		return x.SslProfileId
	}
	return ""
}

type RotateOIakCertResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RotateOIakCertResponse) Reset() {
	*x = RotateOIakCertResponse{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotateOIakCertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateOIakCertResponse) ProtoMessage() {}

func (x *RotateOIakCertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[3]
	if x != nil {
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

type RotateAIKCertRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Value:
	//
	//	*RotateAIKCertRequest_IssuerPublicKey
	//	*RotateAIKCertRequest_IssuerCertPayload_
	//	*RotateAIKCertRequest_Finalize
	Value                isRotateAIKCertRequest_Value             `protobuf_oneof:"value"`
	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,4,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *RotateAIKCertRequest) Reset() {
	*x = RotateAIKCertRequest{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotateAIKCertRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateAIKCertRequest) ProtoMessage() {}

func (x *RotateAIKCertRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotateAIKCertRequest.ProtoReflect.Descriptor instead.
func (*RotateAIKCertRequest) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{4}
}

func (x *RotateAIKCertRequest) GetValue() isRotateAIKCertRequest_Value {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *RotateAIKCertRequest) GetIssuerPublicKey() []byte {
	if x != nil {
		if x, ok := x.Value.(*RotateAIKCertRequest_IssuerPublicKey); ok {
			return x.IssuerPublicKey
		}
	}
	return nil
}

func (x *RotateAIKCertRequest) GetIssuerCertPayload() *RotateAIKCertRequest_IssuerCertPayload {
	if x != nil {
		if x, ok := x.Value.(*RotateAIKCertRequest_IssuerCertPayload_); ok {
			return x.IssuerCertPayload
		}
	}
	return nil
}

func (x *RotateAIKCertRequest) GetFinalize() bool {
	if x != nil {
		if x, ok := x.Value.(*RotateAIKCertRequest_Finalize); ok {
			return x.Finalize
		}
	}
	return false
}

func (x *RotateAIKCertRequest) GetControlCardSelection() *common_definitions.ControlCardSelection {
	if x != nil {
		return x.ControlCardSelection
	}
	return nil
}

type isRotateAIKCertRequest_Value interface {
	isRotateAIKCertRequest_Value()
}

type RotateAIKCertRequest_IssuerPublicKey struct {
	IssuerPublicKey []byte `protobuf:"bytes,1,opt,name=issuer_public_key,json=issuerPublicKey,proto3,oneof"`
}

type RotateAIKCertRequest_IssuerCertPayload_ struct {
	IssuerCertPayload *RotateAIKCertRequest_IssuerCertPayload `protobuf:"bytes,2,opt,name=issuer_cert_payload,json=issuerCertPayload,proto3,oneof"`
}

type RotateAIKCertRequest_Finalize struct {
	Finalize bool `protobuf:"varint,3,opt,name=finalize,proto3,oneof"`
}

func (*RotateAIKCertRequest_IssuerPublicKey) isRotateAIKCertRequest_Value() {}

func (*RotateAIKCertRequest_IssuerCertPayload_) isRotateAIKCertRequest_Value() {}

func (*RotateAIKCertRequest_Finalize) isRotateAIKCertRequest_Value() {}

type RotateAIKCertResponse struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Value:
	//
	//	*RotateAIKCertResponse_ApplicationIdentityRequest
	//	*RotateAIKCertResponse_AikCert
	Value         isRotateAIKCertResponse_Value           `protobuf_oneof:"value"`
	ControlCardId *common_definitions.ControlCardVendorId `protobuf:"bytes,3,opt,name=control_card_id,json=controlCardId,proto3" json:"control_card_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RotateAIKCertResponse) Reset() {
	*x = RotateAIKCertResponse{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotateAIKCertResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateAIKCertResponse) ProtoMessage() {}

func (x *RotateAIKCertResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotateAIKCertResponse.ProtoReflect.Descriptor instead.
func (*RotateAIKCertResponse) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{5}
}

func (x *RotateAIKCertResponse) GetValue() isRotateAIKCertResponse_Value {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *RotateAIKCertResponse) GetApplicationIdentityRequest() []byte {
	if x != nil {
		if x, ok := x.Value.(*RotateAIKCertResponse_ApplicationIdentityRequest); ok {
			return x.ApplicationIdentityRequest
		}
	}
	return nil
}

func (x *RotateAIKCertResponse) GetAikCert() string {
	if x != nil {
		if x, ok := x.Value.(*RotateAIKCertResponse_AikCert); ok {
			return x.AikCert
		}
	}
	return ""
}

func (x *RotateAIKCertResponse) GetControlCardId() *common_definitions.ControlCardVendorId {
	if x != nil {
		return x.ControlCardId
	}
	return nil
}

type isRotateAIKCertResponse_Value interface {
	isRotateAIKCertResponse_Value()
}

type RotateAIKCertResponse_ApplicationIdentityRequest struct {
	ApplicationIdentityRequest []byte `protobuf:"bytes,1,opt,name=application_identity_request,json=applicationIdentityRequest,proto3,oneof"`
}

type RotateAIKCertResponse_AikCert struct {
	AikCert string `protobuf:"bytes,2,opt,name=aik_cert,json=aikCert,proto3,oneof"`
}

func (*RotateAIKCertResponse_ApplicationIdentityRequest) isRotateAIKCertResponse_Value() {}

func (*RotateAIKCertResponse_AikCert) isRotateAIKCertResponse_Value() {}

type RotateAIKCertRequest_IssuerCertPayload struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	SymmetricKeyBlob []byte                 `protobuf:"bytes,1,opt,name=symmetric_key_blob,json=symmetricKeyBlob,proto3" json:"symmetric_key_blob,omitempty"`
	AikCertBlob      []byte                 `protobuf:"bytes,2,opt,name=aik_cert_blob,json=aikCertBlob,proto3" json:"aik_cert_blob,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *RotateAIKCertRequest_IssuerCertPayload) Reset() {
	*x = RotateAIKCertRequest_IssuerCertPayload{}
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RotateAIKCertRequest_IssuerCertPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RotateAIKCertRequest_IssuerCertPayload) ProtoMessage() {}

func (x *RotateAIKCertRequest_IssuerCertPayload) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RotateAIKCertRequest_IssuerCertPayload.ProtoReflect.Descriptor instead.
func (*RotateAIKCertRequest_IssuerCertPayload) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDescGZIP(), []int{4, 0}
}

func (x *RotateAIKCertRequest_IssuerCertPayload) GetSymmetricKeyBlob() []byte {
	if x != nil {
		return x.SymmetricKeyBlob
	}
	return nil
}

func (x *RotateAIKCertRequest_IssuerCertPayload) GetAikCertBlob() []byte {
	if x != nil {
		return x.AikCertBlob
	}
	return nil
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
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74,
	0x70, 0x6d, 0x5f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xeb, 0x01, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x5e, 0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x14, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x19, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x88, 0x01,
	0x01, 0x12, 0x43, 0x0a, 0x09, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x54, 0x70, 0x6d, 0x32, 0x30, 0x48,
	0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x6f, 0x48, 0x01, 0x52, 0x08, 0x68, 0x61, 0x73, 0x68, 0x41,
	0x6c, 0x67, 0x6f, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65,
	0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x22, 0xe3,
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
	0x72, 0x74, 0x12, 0x2c, 0x0a, 0x0f, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x5f, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x0e, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x88, 0x01, 0x01,
	0x42, 0x12, 0x0a, 0x10, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x22, 0xdd, 0x01, 0x0a, 0x15, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x4f,
	0x49, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x5e,
	0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x73,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x14, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b,
	0x0a, 0x09, 0x6f, 0x69, 0x61, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x6f, 0x69, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x6f,
	0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x6f, 0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x43, 0x65, 0x72, 0x74, 0x12, 0x24,
	0x0a, 0x0e, 0x73, 0x73, 0x6c, 0x5f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x69, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x73, 0x6c, 0x50, 0x72, 0x6f, 0x66, 0x69,
	0x6c, 0x65, 0x49, 0x64, 0x22, 0x18, 0x0a, 0x16, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x4f, 0x49,
	0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0xa0,
	0x03, 0x0a, 0x14, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41, 0x49, 0x4b, 0x43, 0x65, 0x72, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x11, 0x69, 0x73, 0x73, 0x75, 0x65,
	0x72, 0x5f, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x48, 0x00, 0x52, 0x0f, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x6c, 0x0a, 0x13, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x5f,
	0x63, 0x65, 0x72, 0x74, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41, 0x49,
	0x4b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x49, 0x73, 0x73,
	0x75, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x48, 0x00,
	0x52, 0x11, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x50, 0x61, 0x79, 0x6c,
	0x6f, 0x61, 0x64, 0x12, 0x1c, 0x0a, 0x08, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x08, 0x48, 0x00, 0x52, 0x08, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a,
	0x65, 0x12, 0x5e, 0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72,
	0x64, 0x5f, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x28, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61,
	0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x14, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x1a, 0x65, 0x0a, 0x11, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x43, 0x65, 0x72, 0x74, 0x50,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x2c, 0x0a, 0x12, 0x73, 0x79, 0x6d, 0x6d, 0x65, 0x74,
	0x72, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x10, 0x73, 0x79, 0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x4b, 0x65, 0x79,
	0x42, 0x6c, 0x6f, 0x62, 0x12, 0x22, 0x0a, 0x0d, 0x61, 0x69, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74,
	0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x61, 0x69, 0x6b,
	0x43, 0x65, 0x72, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x42, 0x07, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x22, 0xd2, 0x01, 0x0a, 0x15, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41, 0x49, 0x4b, 0x43,
	0x65, 0x72, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x42, 0x0a, 0x1c, 0x61,
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x48, 0x00, 0x52, 0x1a, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1b, 0x0a, 0x08, 0x61, 0x69, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x07, 0x61, 0x69, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x4f, 0x0a, 0x0f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x49, 0x64, 0x52, 0x0d,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x49, 0x64, 0x42, 0x07, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32, 0xc3, 0x02, 0x0a, 0x11, 0x54, 0x70, 0x6d, 0x45, 0x6e,
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
	0x73, 0x65, 0x12, 0x68, 0x0a, 0x0d, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41, 0x49, 0x4b, 0x43,
	0x65, 0x72, 0x74, 0x12, 0x28, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41,
	0x49, 0x4b, 0x43, 0x65, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x29, 0x2e,
	0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x7a, 0x2e, 0x52, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x41, 0x49, 0x4b, 0x43, 0x65, 0x72, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x28, 0x01, 0x30, 0x01, 0x42, 0x1f, 0x5a, 0x1d,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_goTypes = []any{
	(*GetIakCertRequest)(nil),                       // 0: openconfig.attestz.GetIakCertRequest
	(*GetIakCertResponse)(nil),                      // 1: openconfig.attestz.GetIakCertResponse
	(*RotateOIakCertRequest)(nil),                   // 2: openconfig.attestz.RotateOIakCertRequest
	(*RotateOIakCertResponse)(nil),                  // 3: openconfig.attestz.RotateOIakCertResponse
	(*RotateAIKCertRequest)(nil),                    // 4: openconfig.attestz.RotateAIKCertRequest
	(*RotateAIKCertResponse)(nil),                   // 5: openconfig.attestz.RotateAIKCertResponse
	(*RotateAIKCertRequest_IssuerCertPayload)(nil),  // 6: openconfig.attestz.RotateAIKCertRequest.IssuerCertPayload
	(*common_definitions.ControlCardSelection)(nil), // 7: openconfig.attestz.ControlCardSelection
	(tpm_attestz.Tpm20HashAlgo)(0),                  // 8: openconfig.attestz.Tpm20HashAlgo
	(*common_definitions.ControlCardVendorId)(nil),  // 9: openconfig.attestz.ControlCardVendorId
}
var file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_depIdxs = []int32{
	7,  // 0: openconfig.attestz.GetIakCertRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	8,  // 1: openconfig.attestz.GetIakCertRequest.hash_algo:type_name -> openconfig.attestz.Tpm20HashAlgo
	9,  // 2: openconfig.attestz.GetIakCertResponse.control_card_id:type_name -> openconfig.attestz.ControlCardVendorId
	7,  // 3: openconfig.attestz.RotateOIakCertRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	6,  // 4: openconfig.attestz.RotateAIKCertRequest.issuer_cert_payload:type_name -> openconfig.attestz.RotateAIKCertRequest.IssuerCertPayload
	7,  // 5: openconfig.attestz.RotateAIKCertRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	9,  // 6: openconfig.attestz.RotateAIKCertResponse.control_card_id:type_name -> openconfig.attestz.ControlCardVendorId
	0,  // 7: openconfig.attestz.TpmEnrollzService.GetIakCert:input_type -> openconfig.attestz.GetIakCertRequest
	2,  // 8: openconfig.attestz.TpmEnrollzService.RotateOIakCert:input_type -> openconfig.attestz.RotateOIakCertRequest
	4,  // 9: openconfig.attestz.TpmEnrollzService.RotateAIKCert:input_type -> openconfig.attestz.RotateAIKCertRequest
	1,  // 10: openconfig.attestz.TpmEnrollzService.GetIakCert:output_type -> openconfig.attestz.GetIakCertResponse
	3,  // 11: openconfig.attestz.TpmEnrollzService.RotateOIakCert:output_type -> openconfig.attestz.RotateOIakCertResponse
	5,  // 12: openconfig.attestz.TpmEnrollzService.RotateAIKCert:output_type -> openconfig.attestz.RotateAIKCertResponse
	10, // [10:13] is the sub-list for method output_type
	7,  // [7:10] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_init() }
func file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_init() {
	if File_github_com_openconfig_attestz_proto_tpm_enrollz_proto != nil {
		return
	}
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[0].OneofWrappers = []any{}
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[1].OneofWrappers = []any{}
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[4].OneofWrappers = []any{
		(*RotateAIKCertRequest_IssuerPublicKey)(nil),
		(*RotateAIKCertRequest_IssuerCertPayload_)(nil),
		(*RotateAIKCertRequest_Finalize)(nil),
	}
	file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_msgTypes[5].OneofWrappers = []any{
		(*RotateAIKCertResponse_ApplicationIdentityRequest)(nil),
		(*RotateAIKCertResponse_AikCert)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_openconfig_attestz_proto_tpm_enrollz_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
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
