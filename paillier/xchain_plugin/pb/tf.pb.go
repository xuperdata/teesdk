// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tf.proto

package pb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SyscallHeader struct {
	Ctxid                int64    `protobuf:"varint,1,opt,name=ctxid,proto3" json:"ctxid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SyscallHeader) Reset()         { *m = SyscallHeader{} }
func (m *SyscallHeader) String() string { return proto.CompactTextString(m) }
func (*SyscallHeader) ProtoMessage()    {}
func (*SyscallHeader) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{0}
}

func (m *SyscallHeader) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SyscallHeader.Unmarshal(m, b)
}
func (m *SyscallHeader) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SyscallHeader.Marshal(b, m, deterministic)
}
func (m *SyscallHeader) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SyscallHeader.Merge(m, src)
}
func (m *SyscallHeader) XXX_Size() int {
	return xxx_messageInfo_SyscallHeader.Size(m)
}
func (m *SyscallHeader) XXX_DiscardUnknown() {
	xxx_messageInfo_SyscallHeader.DiscardUnknown(m)
}

var xxx_messageInfo_SyscallHeader proto.InternalMessageInfo

func (m *SyscallHeader) GetCtxid() int64 {
	if m != nil {
		return m.Ctxid
	}
	return 0
}

type TrustFunctionCallRequest struct {
	Header               *SyscallHeader `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Method               string         `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	Args                 string         `protobuf:"bytes,3,opt,name=args,proto3" json:"args,omitempty"`
	Svn                  uint32         `protobuf:"varint,4,opt,name=svn,proto3" json:"svn,omitempty"`
	Address              string         `protobuf:"bytes,5,opt,name=address,proto3" json:"address,omitempty"`
	PublicKey            string         `protobuf:"bytes,6,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	Signature            string         `protobuf:"bytes,7,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *TrustFunctionCallRequest) Reset()         { *m = TrustFunctionCallRequest{} }
func (m *TrustFunctionCallRequest) String() string { return proto.CompactTextString(m) }
func (*TrustFunctionCallRequest) ProtoMessage()    {}
func (*TrustFunctionCallRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{1}
}

func (m *TrustFunctionCallRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TrustFunctionCallRequest.Unmarshal(m, b)
}
func (m *TrustFunctionCallRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TrustFunctionCallRequest.Marshal(b, m, deterministic)
}
func (m *TrustFunctionCallRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TrustFunctionCallRequest.Merge(m, src)
}
func (m *TrustFunctionCallRequest) XXX_Size() int {
	return xxx_messageInfo_TrustFunctionCallRequest.Size(m)
}
func (m *TrustFunctionCallRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_TrustFunctionCallRequest.DiscardUnknown(m)
}

var xxx_messageInfo_TrustFunctionCallRequest proto.InternalMessageInfo

func (m *TrustFunctionCallRequest) GetHeader() *SyscallHeader {
	if m != nil {
		return m.Header
	}
	return nil
}

func (m *TrustFunctionCallRequest) GetMethod() string {
	if m != nil {
		return m.Method
	}
	return ""
}

func (m *TrustFunctionCallRequest) GetArgs() string {
	if m != nil {
		return m.Args
	}
	return ""
}

func (m *TrustFunctionCallRequest) GetSvn() uint32 {
	if m != nil {
		return m.Svn
	}
	return 0
}

func (m *TrustFunctionCallRequest) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *TrustFunctionCallRequest) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *TrustFunctionCallRequest) GetSignature() string {
	if m != nil {
		return m.Signature
	}
	return ""
}

type KVPair struct {
	Key                  string   `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KVPair) Reset()         { *m = KVPair{} }
func (m *KVPair) String() string { return proto.CompactTextString(m) }
func (*KVPair) ProtoMessage()    {}
func (*KVPair) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{2}
}

func (m *KVPair) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KVPair.Unmarshal(m, b)
}
func (m *KVPair) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KVPair.Marshal(b, m, deterministic)
}
func (m *KVPair) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KVPair.Merge(m, src)
}
func (m *KVPair) XXX_Size() int {
	return xxx_messageInfo_KVPair.Size(m)
}
func (m *KVPair) XXX_DiscardUnknown() {
	xxx_messageInfo_KVPair.DiscardUnknown(m)
}

var xxx_messageInfo_KVPair proto.InternalMessageInfo

func (m *KVPair) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KVPair) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type KVPairs struct {
	Kv                   []*KVPair `protobuf:"bytes,1,rep,name=kv,proto3" json:"kv,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *KVPairs) Reset()         { *m = KVPairs{} }
func (m *KVPairs) String() string { return proto.CompactTextString(m) }
func (*KVPairs) ProtoMessage()    {}
func (*KVPairs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{3}
}

func (m *KVPairs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KVPairs.Unmarshal(m, b)
}
func (m *KVPairs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KVPairs.Marshal(b, m, deterministic)
}
func (m *KVPairs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KVPairs.Merge(m, src)
}
func (m *KVPairs) XXX_Size() int {
	return xxx_messageInfo_KVPairs.Size(m)
}
func (m *KVPairs) XXX_DiscardUnknown() {
	xxx_messageInfo_KVPairs.DiscardUnknown(m)
}

var xxx_messageInfo_KVPairs proto.InternalMessageInfo

func (m *KVPairs) GetKv() []*KVPair {
	if m != nil {
		return m.Kv
	}
	return nil
}

// result of trust call must return a key-value array, key is plain, and value is cipher,
// then be persisted by put_object.
type TrustFunctionCallResponse struct {
	// Types that are valid to be assigned to Results:
	//	*TrustFunctionCallResponse_Plaintext
	//	*TrustFunctionCallResponse_Kvs
	Results              isTrustFunctionCallResponse_Results `protobuf_oneof:"results"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *TrustFunctionCallResponse) Reset()         { *m = TrustFunctionCallResponse{} }
func (m *TrustFunctionCallResponse) String() string { return proto.CompactTextString(m) }
func (*TrustFunctionCallResponse) ProtoMessage()    {}
func (*TrustFunctionCallResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{4}
}

func (m *TrustFunctionCallResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TrustFunctionCallResponse.Unmarshal(m, b)
}
func (m *TrustFunctionCallResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TrustFunctionCallResponse.Marshal(b, m, deterministic)
}
func (m *TrustFunctionCallResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TrustFunctionCallResponse.Merge(m, src)
}
func (m *TrustFunctionCallResponse) XXX_Size() int {
	return xxx_messageInfo_TrustFunctionCallResponse.Size(m)
}
func (m *TrustFunctionCallResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_TrustFunctionCallResponse.DiscardUnknown(m)
}

var xxx_messageInfo_TrustFunctionCallResponse proto.InternalMessageInfo

type isTrustFunctionCallResponse_Results interface {
	isTrustFunctionCallResponse_Results()
}

type TrustFunctionCallResponse_Plaintext struct {
	Plaintext string `protobuf:"bytes,2,opt,name=plaintext,proto3,oneof"`
}

type TrustFunctionCallResponse_Kvs struct {
	Kvs *KVPairs `protobuf:"bytes,3,opt,name=kvs,proto3,oneof"`
}

func (*TrustFunctionCallResponse_Plaintext) isTrustFunctionCallResponse_Results() {}

func (*TrustFunctionCallResponse_Kvs) isTrustFunctionCallResponse_Results() {}

func (m *TrustFunctionCallResponse) GetResults() isTrustFunctionCallResponse_Results {
	if m != nil {
		return m.Results
	}
	return nil
}

func (m *TrustFunctionCallResponse) GetPlaintext() string {
	if x, ok := m.GetResults().(*TrustFunctionCallResponse_Plaintext); ok {
		return x.Plaintext
	}
	return ""
}

func (m *TrustFunctionCallResponse) GetKvs() *KVPairs {
	if x, ok := m.GetResults().(*TrustFunctionCallResponse_Kvs); ok {
		return x.Kvs
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*TrustFunctionCallResponse) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*TrustFunctionCallResponse_Plaintext)(nil),
		(*TrustFunctionCallResponse_Kvs)(nil),
	}
}

// paillier encryption params and outputs
type KeyGenParams struct {
	Secbit               int64    `protobuf:"varint,1,opt,name=secbit,proto3" json:"secbit,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeyGenParams) Reset()         { *m = KeyGenParams{} }
func (m *KeyGenParams) String() string { return proto.CompactTextString(m) }
func (*KeyGenParams) ProtoMessage()    {}
func (*KeyGenParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{5}
}

func (m *KeyGenParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyGenParams.Unmarshal(m, b)
}
func (m *KeyGenParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyGenParams.Marshal(b, m, deterministic)
}
func (m *KeyGenParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyGenParams.Merge(m, src)
}
func (m *KeyGenParams) XXX_Size() int {
	return xxx_messageInfo_KeyGenParams.Size(m)
}
func (m *KeyGenParams) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyGenParams.DiscardUnknown(m)
}

var xxx_messageInfo_KeyGenParams proto.InternalMessageInfo

func (m *KeyGenParams) GetSecbit() int64 {
	if m != nil {
		return m.Secbit
	}
	return 0
}

type KeyGenOutputs struct {
	PrivateKey           string   `protobuf:"bytes,1,opt,name=privateKey,proto3" json:"privateKey,omitempty"`
	PublicKey            string   `protobuf:"bytes,2,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KeyGenOutputs) Reset()         { *m = KeyGenOutputs{} }
func (m *KeyGenOutputs) String() string { return proto.CompactTextString(m) }
func (*KeyGenOutputs) ProtoMessage()    {}
func (*KeyGenOutputs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{6}
}

func (m *KeyGenOutputs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyGenOutputs.Unmarshal(m, b)
}
func (m *KeyGenOutputs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyGenOutputs.Marshal(b, m, deterministic)
}
func (m *KeyGenOutputs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyGenOutputs.Merge(m, src)
}
func (m *KeyGenOutputs) XXX_Size() int {
	return xxx_messageInfo_KeyGenOutputs.Size(m)
}
func (m *KeyGenOutputs) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyGenOutputs.DiscardUnknown(m)
}

var xxx_messageInfo_KeyGenOutputs proto.InternalMessageInfo

func (m *KeyGenOutputs) GetPrivateKey() string {
	if m != nil {
		return m.PrivateKey
	}
	return ""
}

func (m *KeyGenOutputs) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

type PaillierEncParams struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	PublicKey            string   `protobuf:"bytes,2,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierEncParams) Reset()         { *m = PaillierEncParams{} }
func (m *PaillierEncParams) String() string { return proto.CompactTextString(m) }
func (*PaillierEncParams) ProtoMessage()    {}
func (*PaillierEncParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{7}
}

func (m *PaillierEncParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierEncParams.Unmarshal(m, b)
}
func (m *PaillierEncParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierEncParams.Marshal(b, m, deterministic)
}
func (m *PaillierEncParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierEncParams.Merge(m, src)
}
func (m *PaillierEncParams) XXX_Size() int {
	return xxx_messageInfo_PaillierEncParams.Size(m)
}
func (m *PaillierEncParams) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierEncParams.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierEncParams proto.InternalMessageInfo

func (m *PaillierEncParams) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *PaillierEncParams) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

type PaillierEncOutputs struct {
	Ciphertext           string   `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierEncOutputs) Reset()         { *m = PaillierEncOutputs{} }
func (m *PaillierEncOutputs) String() string { return proto.CompactTextString(m) }
func (*PaillierEncOutputs) ProtoMessage()    {}
func (*PaillierEncOutputs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{8}
}

func (m *PaillierEncOutputs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierEncOutputs.Unmarshal(m, b)
}
func (m *PaillierEncOutputs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierEncOutputs.Marshal(b, m, deterministic)
}
func (m *PaillierEncOutputs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierEncOutputs.Merge(m, src)
}
func (m *PaillierEncOutputs) XXX_Size() int {
	return xxx_messageInfo_PaillierEncOutputs.Size(m)
}
func (m *PaillierEncOutputs) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierEncOutputs.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierEncOutputs proto.InternalMessageInfo

func (m *PaillierEncOutputs) GetCiphertext() string {
	if m != nil {
		return m.Ciphertext
	}
	return ""
}

type PaillierDecParams struct {
	Ciphertext           string   `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	PublicKey            string   `protobuf:"bytes,2,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	PrvkeyPath           string   `protobuf:"bytes,3,opt,name=prvkeyPath,proto3" json:"prvkeyPath,omitempty"`
	Password             string   `protobuf:"bytes,4,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierDecParams) Reset()         { *m = PaillierDecParams{} }
func (m *PaillierDecParams) String() string { return proto.CompactTextString(m) }
func (*PaillierDecParams) ProtoMessage()    {}
func (*PaillierDecParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{9}
}

func (m *PaillierDecParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierDecParams.Unmarshal(m, b)
}
func (m *PaillierDecParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierDecParams.Marshal(b, m, deterministic)
}
func (m *PaillierDecParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierDecParams.Merge(m, src)
}
func (m *PaillierDecParams) XXX_Size() int {
	return xxx_messageInfo_PaillierDecParams.Size(m)
}
func (m *PaillierDecParams) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierDecParams.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierDecParams proto.InternalMessageInfo

func (m *PaillierDecParams) GetCiphertext() string {
	if m != nil {
		return m.Ciphertext
	}
	return ""
}

func (m *PaillierDecParams) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *PaillierDecParams) GetPrvkeyPath() string {
	if m != nil {
		return m.PrvkeyPath
	}
	return ""
}

func (m *PaillierDecParams) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type PaillierDecOutputs struct {
	Plaintext            uint64   `protobuf:"varint,1,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierDecOutputs) Reset()         { *m = PaillierDecOutputs{} }
func (m *PaillierDecOutputs) String() string { return proto.CompactTextString(m) }
func (*PaillierDecOutputs) ProtoMessage()    {}
func (*PaillierDecOutputs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{10}
}

func (m *PaillierDecOutputs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierDecOutputs.Unmarshal(m, b)
}
func (m *PaillierDecOutputs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierDecOutputs.Marshal(b, m, deterministic)
}
func (m *PaillierDecOutputs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierDecOutputs.Merge(m, src)
}
func (m *PaillierDecOutputs) XXX_Size() int {
	return xxx_messageInfo_PaillierDecOutputs.Size(m)
}
func (m *PaillierDecOutputs) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierDecOutputs.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierDecOutputs proto.InternalMessageInfo

func (m *PaillierDecOutputs) GetPlaintext() uint64 {
	if m != nil {
		return m.Plaintext
	}
	return 0
}

type PaillierMulParams struct {
	PublicKey            string   `protobuf:"bytes,1,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	Ciphertext1          string   `protobuf:"bytes,2,opt,name=ciphertext1,proto3" json:"ciphertext1,omitempty"`
	Ciphertext2          string   `protobuf:"bytes,3,opt,name=ciphertext2,proto3" json:"ciphertext2,omitempty"`
	Commitment1          string   `protobuf:"bytes,4,opt,name=commitment1,proto3" json:"commitment1,omitempty"`
	Commitment2          string   `protobuf:"bytes,5,opt,name=commitment2,proto3" json:"commitment2,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierMulParams) Reset()         { *m = PaillierMulParams{} }
func (m *PaillierMulParams) String() string { return proto.CompactTextString(m) }
func (*PaillierMulParams) ProtoMessage()    {}
func (*PaillierMulParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{11}
}

func (m *PaillierMulParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierMulParams.Unmarshal(m, b)
}
func (m *PaillierMulParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierMulParams.Marshal(b, m, deterministic)
}
func (m *PaillierMulParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierMulParams.Merge(m, src)
}
func (m *PaillierMulParams) XXX_Size() int {
	return xxx_messageInfo_PaillierMulParams.Size(m)
}
func (m *PaillierMulParams) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierMulParams.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierMulParams proto.InternalMessageInfo

func (m *PaillierMulParams) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *PaillierMulParams) GetCiphertext1() string {
	if m != nil {
		return m.Ciphertext1
	}
	return ""
}

func (m *PaillierMulParams) GetCiphertext2() string {
	if m != nil {
		return m.Ciphertext2
	}
	return ""
}

func (m *PaillierMulParams) GetCommitment1() string {
	if m != nil {
		return m.Commitment1
	}
	return ""
}

func (m *PaillierMulParams) GetCommitment2() string {
	if m != nil {
		return m.Commitment2
	}
	return ""
}

type PaillierMulOutputs struct {
	Ciphertext           string   `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierMulOutputs) Reset()         { *m = PaillierMulOutputs{} }
func (m *PaillierMulOutputs) String() string { return proto.CompactTextString(m) }
func (*PaillierMulOutputs) ProtoMessage()    {}
func (*PaillierMulOutputs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{12}
}

func (m *PaillierMulOutputs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierMulOutputs.Unmarshal(m, b)
}
func (m *PaillierMulOutputs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierMulOutputs.Marshal(b, m, deterministic)
}
func (m *PaillierMulOutputs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierMulOutputs.Merge(m, src)
}
func (m *PaillierMulOutputs) XXX_Size() int {
	return xxx_messageInfo_PaillierMulOutputs.Size(m)
}
func (m *PaillierMulOutputs) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierMulOutputs.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierMulOutputs proto.InternalMessageInfo

func (m *PaillierMulOutputs) GetCiphertext() string {
	if m != nil {
		return m.Ciphertext
	}
	return ""
}

type PaillierExpParams struct {
	PublicKey            string   `protobuf:"bytes,1,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	Ciphertext           string   `protobuf:"bytes,2,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	Commitment           string   `protobuf:"bytes,3,opt,name=commitment,proto3" json:"commitment,omitempty"`
	Scalar               string   `protobuf:"bytes,4,opt,name=scalar,proto3" json:"scalar,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierExpParams) Reset()         { *m = PaillierExpParams{} }
func (m *PaillierExpParams) String() string { return proto.CompactTextString(m) }
func (*PaillierExpParams) ProtoMessage()    {}
func (*PaillierExpParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{13}
}

func (m *PaillierExpParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierExpParams.Unmarshal(m, b)
}
func (m *PaillierExpParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierExpParams.Marshal(b, m, deterministic)
}
func (m *PaillierExpParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierExpParams.Merge(m, src)
}
func (m *PaillierExpParams) XXX_Size() int {
	return xxx_messageInfo_PaillierExpParams.Size(m)
}
func (m *PaillierExpParams) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierExpParams.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierExpParams proto.InternalMessageInfo

func (m *PaillierExpParams) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *PaillierExpParams) GetCiphertext() string {
	if m != nil {
		return m.Ciphertext
	}
	return ""
}

func (m *PaillierExpParams) GetCommitment() string {
	if m != nil {
		return m.Commitment
	}
	return ""
}

func (m *PaillierExpParams) GetScalar() string {
	if m != nil {
		return m.Scalar
	}
	return ""
}

type PaillierExpOutputs struct {
	Ciphertext           string   `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PaillierExpOutputs) Reset()         { *m = PaillierExpOutputs{} }
func (m *PaillierExpOutputs) String() string { return proto.CompactTextString(m) }
func (*PaillierExpOutputs) ProtoMessage()    {}
func (*PaillierExpOutputs) Descriptor() ([]byte, []int) {
	return fileDescriptor_375fc9137751f710, []int{14}
}

func (m *PaillierExpOutputs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PaillierExpOutputs.Unmarshal(m, b)
}
func (m *PaillierExpOutputs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PaillierExpOutputs.Marshal(b, m, deterministic)
}
func (m *PaillierExpOutputs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PaillierExpOutputs.Merge(m, src)
}
func (m *PaillierExpOutputs) XXX_Size() int {
	return xxx_messageInfo_PaillierExpOutputs.Size(m)
}
func (m *PaillierExpOutputs) XXX_DiscardUnknown() {
	xxx_messageInfo_PaillierExpOutputs.DiscardUnknown(m)
}

var xxx_messageInfo_PaillierExpOutputs proto.InternalMessageInfo

func (m *PaillierExpOutputs) GetCiphertext() string {
	if m != nil {
		return m.Ciphertext
	}
	return ""
}

func init() {
	proto.RegisterType((*SyscallHeader)(nil), "SyscallHeader")
	proto.RegisterType((*TrustFunctionCallRequest)(nil), "TrustFunctionCallRequest")
	proto.RegisterType((*KVPair)(nil), "KVPair")
	proto.RegisterType((*KVPairs)(nil), "KVPairs")
	proto.RegisterType((*TrustFunctionCallResponse)(nil), "TrustFunctionCallResponse")
	proto.RegisterType((*KeyGenParams)(nil), "KeyGenParams")
	proto.RegisterType((*KeyGenOutputs)(nil), "KeyGenOutputs")
	proto.RegisterType((*PaillierEncParams)(nil), "PaillierEncParams")
	proto.RegisterType((*PaillierEncOutputs)(nil), "PaillierEncOutputs")
	proto.RegisterType((*PaillierDecParams)(nil), "PaillierDecParams")
	proto.RegisterType((*PaillierDecOutputs)(nil), "PaillierDecOutputs")
	proto.RegisterType((*PaillierMulParams)(nil), "PaillierMulParams")
	proto.RegisterType((*PaillierMulOutputs)(nil), "PaillierMulOutputs")
	proto.RegisterType((*PaillierExpParams)(nil), "PaillierExpParams")
	proto.RegisterType((*PaillierExpOutputs)(nil), "PaillierExpOutputs")
}

func init() {
	proto.RegisterFile("tf.proto", fileDescriptor_375fc9137751f710)
}

var fileDescriptor_375fc9137751f710 = []byte{
	// 620 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0xdd, 0x6e, 0xd3, 0x30,
	0x14, 0x5e, 0xda, 0xad, 0x5d, 0x4f, 0x19, 0x02, 0x0b, 0x41, 0x40, 0xd3, 0x54, 0x45, 0x62, 0xea,
	0x55, 0xcb, 0x0a, 0x12, 0x17, 0xdc, 0x8d, 0x0d, 0x2a, 0x55, 0x13, 0x55, 0x40, 0x5c, 0x70, 0x83,
	0xdc, 0xe4, 0xd0, 0x58, 0x75, 0x9c, 0x60, 0x3b, 0x59, 0xfb, 0x08, 0x5c, 0xf0, 0x40, 0xbc, 0x08,
	0xcf, 0x83, 0x92, 0xb8, 0x8d, 0x33, 0x10, 0xdb, 0x9d, 0xcf, 0x77, 0x7e, 0xf2, 0x7d, 0xdf, 0xb1,
	0x03, 0x87, 0xfa, 0xdb, 0x28, 0x95, 0x89, 0x4e, 0xbc, 0xe7, 0x70, 0xf4, 0x71, 0xa3, 0x02, 0xca,
	0xf9, 0x14, 0x69, 0x88, 0x92, 0x3c, 0x82, 0x83, 0x40, 0xaf, 0x59, 0xe8, 0x3a, 0x03, 0x67, 0xd8,
	0xf6, 0xab, 0xc0, 0xfb, 0xed, 0x80, 0xfb, 0x49, 0x66, 0x4a, 0xbf, 0xcb, 0x44, 0xa0, 0x59, 0x22,
	0xde, 0x52, 0xce, 0x7d, 0xfc, 0x9e, 0xa1, 0xd2, 0xe4, 0x14, 0x3a, 0x51, 0xd9, 0x5c, 0xf6, 0xf4,
	0x27, 0xf7, 0x47, 0x8d, 0x91, 0xbe, 0xc9, 0x92, 0xc7, 0xd0, 0x89, 0x51, 0x47, 0x49, 0xe8, 0xb6,
	0x06, 0xce, 0xb0, 0xe7, 0x9b, 0x88, 0x10, 0xd8, 0xa7, 0x72, 0xa9, 0xdc, 0x76, 0x89, 0x96, 0x67,
	0xf2, 0x00, 0xda, 0x2a, 0x17, 0xee, 0xfe, 0xc0, 0x19, 0x1e, 0xf9, 0xc5, 0x91, 0xb8, 0xd0, 0xa5,
	0x61, 0x28, 0x51, 0x29, 0xf7, 0xa0, 0x2c, 0xdc, 0x86, 0xe4, 0x18, 0x7a, 0x69, 0xb6, 0xe0, 0x2c,
	0x98, 0xe1, 0xc6, 0xed, 0x94, 0xb9, 0x1a, 0x28, 0xb2, 0x8a, 0x2d, 0x05, 0xd5, 0x99, 0x44, 0xb7,
	0x5b, 0x65, 0x77, 0x80, 0xf7, 0x02, 0x3a, 0xb3, 0xcf, 0x73, 0xca, 0x64, 0xf1, 0xc5, 0x15, 0x6e,
	0x4a, 0x09, 0x3d, 0xbf, 0x38, 0x16, 0x56, 0xe4, 0x94, 0x67, 0x68, 0xe8, 0x56, 0x81, 0xe7, 0x41,
	0xb7, 0xea, 0x50, 0xe4, 0x09, 0xb4, 0x56, 0xb9, 0xeb, 0x0c, 0xda, 0xc3, 0xfe, 0xa4, 0x3b, 0xaa,
	0x50, 0xbf, 0xb5, 0xca, 0xbd, 0x10, 0x9e, 0xfe, 0xc3, 0x2d, 0x95, 0x26, 0x42, 0x21, 0x39, 0x81,
	0x5e, 0xca, 0x29, 0x13, 0x1a, 0xd7, 0xba, 0x1a, 0x3d, 0xdd, 0xf3, 0x6b, 0x88, 0x1c, 0x43, 0x7b,
	0x95, 0x57, 0x6e, 0xf4, 0x27, 0x87, 0x66, 0xac, 0x9a, 0xee, 0xf9, 0x05, 0x7c, 0xde, 0x83, 0xae,
	0x44, 0x95, 0x71, 0xad, 0xbc, 0x53, 0xb8, 0x37, 0xc3, 0xcd, 0x7b, 0x14, 0x73, 0x2a, 0x69, 0xac,
	0x0a, 0x7f, 0x15, 0x06, 0x0b, 0xa6, 0xcd, 0xee, 0x4c, 0xe4, 0x5d, 0xc1, 0x51, 0x55, 0xf7, 0x21,
	0xd3, 0x69, 0xa6, 0x15, 0x39, 0x01, 0x48, 0x25, 0xcb, 0xa9, 0xc6, 0xd9, 0x4e, 0xb1, 0x85, 0x34,
	0x0d, 0x6d, 0xdd, 0x30, 0xd4, 0x9b, 0xc1, 0xc3, 0x39, 0x65, 0x9c, 0x33, 0x94, 0x97, 0x22, 0x30,
	0xdf, 0x76, 0xa1, 0x1b, 0xa3, 0x52, 0x74, 0x89, 0x66, 0xde, 0x36, 0xbc, 0x65, 0xd8, 0x2b, 0x20,
	0xd6, 0x30, 0x8b, 0x60, 0xc0, 0xd2, 0x08, 0x65, 0xe9, 0x91, 0x21, 0x58, 0x23, 0xde, 0x4f, 0xa7,
	0xe6, 0x70, 0x81, 0x5b, 0x0e, 0xb7, 0x74, 0xfd, 0x9f, 0x49, 0x65, 0x4a, 0xbe, 0xc2, 0xcd, 0x9c,
	0xea, 0xc8, 0xdc, 0x45, 0x0b, 0x21, 0xcf, 0xe0, 0x30, 0xa5, 0x4a, 0x5d, 0x27, 0x32, 0x2c, 0xaf,
	0x65, 0xcf, 0xdf, 0xc5, 0xde, 0xa4, 0x56, 0x71, 0x81, 0x3b, 0x15, 0xc7, 0xf6, 0xa2, 0x0b, 0x3a,
	0xfb, 0xd6, 0x9a, 0xbd, 0x5f, 0x96, 0x86, 0xab, 0x8c, 0x1b, 0x0d, 0x0d, 0x8e, 0xce, 0x4d, 0x8e,
	0x03, 0xe8, 0xd7, 0x7a, 0xce, 0x8c, 0x06, 0x1b, 0x6a, 0x56, 0x4c, 0x8c, 0x0c, 0x1b, 0x2a, 0x2b,
	0x92, 0x38, 0x66, 0x3a, 0x46, 0xa1, 0xcf, 0x8c, 0x14, 0x1b, 0x6a, 0x56, 0x4c, 0xcc, 0x6b, 0xb3,
	0x21, 0x7b, 0x6b, 0x57, 0x19, 0xbf, 0xeb, 0xd6, 0x7e, 0x58, 0x8a, 0x2f, 0xd7, 0xe9, 0x9d, 0x14,
	0x37, 0x67, 0xb6, 0xfe, 0xda, 0x69, 0x91, 0xdf, 0x11, 0xdb, 0x6e, 0xad, 0x46, 0xca, 0x37, 0x11,
	0x50, 0x4e, 0xa5, 0x11, 0x6a, 0xa2, 0xc6, 0xbd, 0x5b, 0xa7, 0x77, 0x54, 0x70, 0xfe, 0x66, 0xda,
	0xfe, 0xf2, 0x7a, 0xc9, 0x74, 0x94, 0x2d, 0x46, 0x41, 0x12, 0x8f, 0xa3, 0x44, 0x2c, 0x37, 0x54,
	0x5c, 0x53, 0xb1, 0x1c, 0x6b, 0x44, 0x15, 0xae, 0xc6, 0xa9, 0x99, 0x3a, 0x5e, 0x07, 0x11, 0x65,
	0xe2, 0x6b, 0xca, 0xb3, 0x25, 0x13, 0xe3, 0x74, 0xb1, 0xe8, 0x94, 0x7f, 0xdc, 0x97, 0x7f, 0x02,
	0x00, 0x00, 0xff, 0xff, 0x24, 0x9c, 0xaf, 0x58, 0x7d, 0x05, 0x00, 0x00,
}