// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.10
// source: github.com/openconfig/attestz/proto/tpm_attestz.proto

package attestz

import (
	common_definitions "github.com/openconfig/attestz/proto/common_definitions"
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

type Tpm20HashAlgo int32

const (
	Tpm20HashAlgo_TPM20HASH_ALGO_UNSPECIFIED Tpm20HashAlgo = 0
	Tpm20HashAlgo_TPM20HASH_ALGO_SHA1        Tpm20HashAlgo = 1
	Tpm20HashAlgo_TPM20HASH_ALGO_SHA256      Tpm20HashAlgo = 2
	Tpm20HashAlgo_TPM20HASH_ALGO_SHA384      Tpm20HashAlgo = 3
	Tpm20HashAlgo_TPM20HASH_ALGO_SHA512      Tpm20HashAlgo = 4
)

// Enum value maps for Tpm20HashAlgo.
var (
	Tpm20HashAlgo_name = map[int32]string{
		0: "TPM20HASH_ALGO_UNSPECIFIED",
		1: "TPM20HASH_ALGO_SHA1",
		2: "TPM20HASH_ALGO_SHA256",
		3: "TPM20HASH_ALGO_SHA384",
		4: "TPM20HASH_ALGO_SHA512",
	}
	Tpm20HashAlgo_value = map[string]int32{
		"TPM20HASH_ALGO_UNSPECIFIED": 0,
		"TPM20HASH_ALGO_SHA1":        1,
		"TPM20HASH_ALGO_SHA256":      2,
		"TPM20HASH_ALGO_SHA384":      3,
		"TPM20HASH_ALGO_SHA512":      4,
	}
)

func (x Tpm20HashAlgo) Enum() *Tpm20HashAlgo {
	p := new(Tpm20HashAlgo)
	*p = x
	return p
}

func (x Tpm20HashAlgo) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Tpm20HashAlgo) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_enumTypes[0].Descriptor()
}

func (Tpm20HashAlgo) Type() protoreflect.EnumType {
	return &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_enumTypes[0]
}

func (x Tpm20HashAlgo) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Tpm20HashAlgo.Descriptor instead.
func (Tpm20HashAlgo) EnumDescriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescGZIP(), []int{0}
}

type AttestRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControlCardSelection *common_definitions.ControlCardSelection `protobuf:"bytes,1,opt,name=control_card_selection,json=controlCardSelection,proto3" json:"control_card_selection,omitempty"`
	Nonce                []byte                                   `protobuf:"bytes,2,opt,name=nonce,proto3" json:"nonce,omitempty"`
	HashAlgo             Tpm20HashAlgo                            `protobuf:"varint,3,opt,name=hash_algo,json=hashAlgo,proto3,enum=openconfig.attestz.Tpm20HashAlgo" json:"hash_algo,omitempty"`
	PcrIndices           []int32                                  `protobuf:"varint,4,rep,packed,name=pcr_indices,json=pcrIndices,proto3" json:"pcr_indices,omitempty"`
}

func (x *AttestRequest) Reset() {
	*x = AttestRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestRequest) ProtoMessage() {}

func (x *AttestRequest) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestRequest.ProtoReflect.Descriptor instead.
func (*AttestRequest) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescGZIP(), []int{0}
}

func (x *AttestRequest) GetControlCardSelection() *common_definitions.ControlCardSelection {
	if x != nil {
		return x.ControlCardSelection
	}
	return nil
}

func (x *AttestRequest) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *AttestRequest) GetHashAlgo() Tpm20HashAlgo {
	if x != nil {
		return x.HashAlgo
	}
	return Tpm20HashAlgo_TPM20HASH_ALGO_UNSPECIFIED
}

func (x *AttestRequest) GetPcrIndices() []int32 {
	if x != nil {
		return x.PcrIndices
	}
	return nil
}

type AttestResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControlCardId *common_definitions.ControlCardVendorId `protobuf:"bytes,1,opt,name=control_card_id,json=controlCardId,proto3" json:"control_card_id,omitempty"`
	// Deprecated: Marked as deprecated in github.com/openconfig/attestz/proto/tpm_attestz.proto.
	OiakCert        string                          `protobuf:"bytes,2,opt,name=oiak_cert,json=oiakCert,proto3" json:"oiak_cert,omitempty"`
	PcrValues       map[int32][]byte                `protobuf:"bytes,3,rep,name=pcr_values,json=pcrValues,proto3" json:"pcr_values,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Quoted          []byte                          `protobuf:"bytes,4,opt,name=quoted,proto3" json:"quoted,omitempty"`
	QuoteSignature  []byte                          `protobuf:"bytes,5,opt,name=quote_signature,json=quoteSignature,proto3" json:"quote_signature,omitempty"`
	OidevidCert     string                          `protobuf:"bytes,6,opt,name=oidevid_cert,json=oidevidCert,proto3" json:"oidevid_cert,omitempty"`
	AttestationCert *AttestResponse_AttestationCert `protobuf:"bytes,7,opt,name=attestation_cert,json=attestationCert,proto3" json:"attestation_cert,omitempty"`
}

func (x *AttestResponse) Reset() {
	*x = AttestResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestResponse) ProtoMessage() {}

func (x *AttestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestResponse.ProtoReflect.Descriptor instead.
func (*AttestResponse) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescGZIP(), []int{1}
}

func (x *AttestResponse) GetControlCardId() *common_definitions.ControlCardVendorId {
	if x != nil {
		return x.ControlCardId
	}
	return nil
}

// Deprecated: Marked as deprecated in github.com/openconfig/attestz/proto/tpm_attestz.proto.
func (x *AttestResponse) GetOiakCert() string {
	if x != nil {
		return x.OiakCert
	}
	return ""
}

func (x *AttestResponse) GetPcrValues() map[int32][]byte {
	if x != nil {
		return x.PcrValues
	}
	return nil
}

func (x *AttestResponse) GetQuoted() []byte {
	if x != nil {
		return x.Quoted
	}
	return nil
}

func (x *AttestResponse) GetQuoteSignature() []byte {
	if x != nil {
		return x.QuoteSignature
	}
	return nil
}

func (x *AttestResponse) GetOidevidCert() string {
	if x != nil {
		return x.OidevidCert
	}
	return ""
}

func (x *AttestResponse) GetAttestationCert() *AttestResponse_AttestationCert {
	if x != nil {
		return x.AttestationCert
	}
	return nil
}

type AttestResponse_AttestationCert struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Value:
	//
	//	*AttestResponse_AttestationCert_AikCert
	//	*AttestResponse_AttestationCert_OiakCert
	Value isAttestResponse_AttestationCert_Value `protobuf_oneof:"value"`
}

func (x *AttestResponse_AttestationCert) Reset() {
	*x = AttestResponse_AttestationCert{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttestResponse_AttestationCert) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestResponse_AttestationCert) ProtoMessage() {}

func (x *AttestResponse_AttestationCert) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestResponse_AttestationCert.ProtoReflect.Descriptor instead.
func (*AttestResponse_AttestationCert) Descriptor() ([]byte, []int) {
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescGZIP(), []int{1, 0}
}

func (m *AttestResponse_AttestationCert) GetValue() isAttestResponse_AttestationCert_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (x *AttestResponse_AttestationCert) GetAikCert() string {
	if x, ok := x.GetValue().(*AttestResponse_AttestationCert_AikCert); ok {
		return x.AikCert
	}
	return ""
}

func (x *AttestResponse_AttestationCert) GetOiakCert() string {
	if x, ok := x.GetValue().(*AttestResponse_AttestationCert_OiakCert); ok {
		return x.OiakCert
	}
	return ""
}

type isAttestResponse_AttestationCert_Value interface {
	isAttestResponse_AttestationCert_Value()
}

type AttestResponse_AttestationCert_AikCert struct {
	AikCert string `protobuf:"bytes,1,opt,name=aik_cert,json=aikCert,proto3,oneof"`
}

type AttestResponse_AttestationCert_OiakCert struct {
	OiakCert string `protobuf:"bytes,2,opt,name=oiak_cert,json=oiakCert,proto3,oneof"`
}

func (*AttestResponse_AttestationCert_AikCert) isAttestResponse_AttestationCert_Value() {}

func (*AttestResponse_AttestationCert_OiakCert) isAttestResponse_AttestationCert_Value() {}

var File_github_com_openconfig_attestz_proto_tpm_attestz_proto protoreflect.FileDescriptor

var file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDesc = []byte{
	0x0a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65,
	0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x70, 0x6d, 0x5f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x7a, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x1a, 0x3c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe6, 0x01, 0x0a, 0x0d, 0x41, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x5e, 0x0a, 0x16, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x73, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x6f, 0x70,
	0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a,
	0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x53, 0x65, 0x6c, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x14, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61,
	0x72, 0x64, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63,
	0x65, 0x12, 0x3e, 0x0a, 0x09, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x61, 0x6c, 0x67, 0x6f, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x54, 0x70, 0x6d, 0x32, 0x30, 0x48,
	0x61, 0x73, 0x68, 0x41, 0x6c, 0x67, 0x6f, 0x52, 0x08, 0x68, 0x61, 0x73, 0x68, 0x41, 0x6c, 0x67,
	0x6f, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x63, 0x72, 0x5f, 0x69, 0x6e, 0x64, 0x69, 0x63, 0x65, 0x73,
	0x18, 0x04, 0x20, 0x03, 0x28, 0x05, 0x52, 0x0a, 0x70, 0x63, 0x72, 0x49, 0x6e, 0x64, 0x69, 0x63,
	0x65, 0x73, 0x22, 0xad, 0x04, 0x0a, 0x0e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4f, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27,
	0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x7a, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x43, 0x61, 0x72, 0x64, 0x56,
	0x65, 0x6e, 0x64, 0x6f, 0x72, 0x49, 0x64, 0x52, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x43, 0x61, 0x72, 0x64, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x09, 0x6f, 0x69, 0x61, 0x6b, 0x5f, 0x63,
	0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01, 0x52, 0x08, 0x6f,
	0x69, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x50, 0x0a, 0x0a, 0x70, 0x63, 0x72, 0x5f, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x6f, 0x70,
	0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a,
	0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e,
	0x50, 0x63, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09,
	0x70, 0x63, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x71, 0x75, 0x6f,
	0x74, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x71, 0x75, 0x6f, 0x74, 0x65,
	0x64, 0x12, 0x27, 0x0a, 0x0f, 0x71, 0x75, 0x6f, 0x74, 0x65, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x71, 0x75, 0x6f, 0x74,
	0x65, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x69,
	0x64, 0x65, 0x76, 0x69, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x6f, 0x69, 0x64, 0x65, 0x76, 0x69, 0x64, 0x43, 0x65, 0x72, 0x74, 0x12, 0x5d, 0x0a,
	0x10, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x65, 0x72,
	0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x41, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x41, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x52, 0x0f, 0x61, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x1a, 0x56, 0x0a, 0x0f,
	0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x65, 0x72, 0x74, 0x12,
	0x1b, 0x0a, 0x08, 0x61, 0x69, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x07, 0x61, 0x69, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x12, 0x1d, 0x0a, 0x09,
	0x6f, 0x69, 0x61, 0x6b, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x08, 0x6f, 0x69, 0x61, 0x6b, 0x43, 0x65, 0x72, 0x74, 0x42, 0x07, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x1a, 0x3c, 0x0a, 0x0e, 0x50, 0x63, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x2a, 0x99, 0x01, 0x0a, 0x0d, 0x54, 0x70, 0x6d, 0x32, 0x30, 0x48, 0x61, 0x73, 0x68,
	0x41, 0x6c, 0x67, 0x6f, 0x12, 0x1e, 0x0a, 0x1a, 0x54, 0x50, 0x4d, 0x32, 0x30, 0x48, 0x41, 0x53,
	0x48, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49,
	0x45, 0x44, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x54, 0x50, 0x4d, 0x32, 0x30, 0x48, 0x41, 0x53,
	0x48, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x5f, 0x53, 0x48, 0x41, 0x31, 0x10, 0x01, 0x12, 0x19, 0x0a,
	0x15, 0x54, 0x50, 0x4d, 0x32, 0x30, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x5f,
	0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x10, 0x02, 0x12, 0x19, 0x0a, 0x15, 0x54, 0x50, 0x4d, 0x32,
	0x30, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x5f, 0x53, 0x48, 0x41, 0x33, 0x38,
	0x34, 0x10, 0x03, 0x12, 0x19, 0x0a, 0x15, 0x54, 0x50, 0x4d, 0x32, 0x30, 0x48, 0x41, 0x53, 0x48,
	0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x5f, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32, 0x10, 0x04, 0x32, 0x64,
	0x0a, 0x11, 0x54, 0x70, 0x6d, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x7a, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x12, 0x4f, 0x0a, 0x06, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x12, 0x21, 0x2e,
	0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x7a, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x22, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x7a, 0x2e, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x42, 0x1f, 0x5a, 0x1d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x7a, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescOnce sync.Once
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescData = file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDesc
)

func file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescGZIP() []byte {
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescOnce.Do(func() {
		file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescData)
	})
	return file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDescData
}

var file_github_com_openconfig_attestz_proto_tpm_attestz_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_github_com_openconfig_attestz_proto_tpm_attestz_proto_goTypes = []interface{}{
	(Tpm20HashAlgo)(0),                     // 0: openconfig.attestz.Tpm20HashAlgo
	(*AttestRequest)(nil),                  // 1: openconfig.attestz.AttestRequest
	(*AttestResponse)(nil),                 // 2: openconfig.attestz.AttestResponse
	(*AttestResponse_AttestationCert)(nil), // 3: openconfig.attestz.AttestResponse.AttestationCert
	nil,                                    // 4: openconfig.attestz.AttestResponse.PcrValuesEntry
	(*common_definitions.ControlCardSelection)(nil), // 5: openconfig.attestz.ControlCardSelection
	(*common_definitions.ControlCardVendorId)(nil),  // 6: openconfig.attestz.ControlCardVendorId
}
var file_github_com_openconfig_attestz_proto_tpm_attestz_proto_depIdxs = []int32{
	5, // 0: openconfig.attestz.AttestRequest.control_card_selection:type_name -> openconfig.attestz.ControlCardSelection
	0, // 1: openconfig.attestz.AttestRequest.hash_algo:type_name -> openconfig.attestz.Tpm20HashAlgo
	6, // 2: openconfig.attestz.AttestResponse.control_card_id:type_name -> openconfig.attestz.ControlCardVendorId
	4, // 3: openconfig.attestz.AttestResponse.pcr_values:type_name -> openconfig.attestz.AttestResponse.PcrValuesEntry
	3, // 4: openconfig.attestz.AttestResponse.attestation_cert:type_name -> openconfig.attestz.AttestResponse.AttestationCert
	1, // 5: openconfig.attestz.TpmAttestzService.Attest:input_type -> openconfig.attestz.AttestRequest
	2, // 6: openconfig.attestz.TpmAttestzService.Attest:output_type -> openconfig.attestz.AttestResponse
	6, // [6:7] is the sub-list for method output_type
	5, // [5:6] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_github_com_openconfig_attestz_proto_tpm_attestz_proto_init() }
func file_github_com_openconfig_attestz_proto_tpm_attestz_proto_init() {
	if File_github_com_openconfig_attestz_proto_tpm_attestz_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestRequest); i {
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
		file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestResponse); i {
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
		file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttestResponse_AttestationCert); i {
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
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*AttestResponse_AttestationCert_AikCert)(nil),
		(*AttestResponse_AttestationCert_OiakCert)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_github_com_openconfig_attestz_proto_tpm_attestz_proto_goTypes,
		DependencyIndexes: file_github_com_openconfig_attestz_proto_tpm_attestz_proto_depIdxs,
		EnumInfos:         file_github_com_openconfig_attestz_proto_tpm_attestz_proto_enumTypes,
		MessageInfos:      file_github_com_openconfig_attestz_proto_tpm_attestz_proto_msgTypes,
	}.Build()
	File_github_com_openconfig_attestz_proto_tpm_attestz_proto = out.File
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_rawDesc = nil
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_goTypes = nil
	file_github_com_openconfig_attestz_proto_tpm_attestz_proto_depIdxs = nil
}
