package biz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	tpm20 "github.com/google/go-tpm/tpm2"
)

var (
	// Constants to be used in request params and stubbing.
	validTPMTPublic = tpm20.TPMTPublic{
		Type:             tpm20.TPMAlgECC,
		NameAlg:          tpm20.TPMAlgSHA256,
		ObjectAttributes: tpm20.TPMAObject{},
		AuthPolicy: tpm20.TPM2BDigest{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		},
		Parameters: tpm20.NewTPMUPublicParms(tpm20.TPMAlgECC, &tpm20.TPMSECCParms{
			Symmetric: tpm20.TPMTSymDefObject{Algorithm: tpm20.TPMAlgNull},
			Scheme: tpm20.TPMTECCScheme{
				Scheme: tpm20.TPMAlgECDSA,
				Details: tpm20.NewTPMUAsymScheme(tpm20.TPMAlgECDSA, &tpm20.TPMSSigSchemeECDSA{
					HashAlg: tpm20.TPMAlgSHA256,
				}),
			},
			CurveID: tpm20.TPMECCNistP256,
			KDF:     tpm20.TPMTKDFScheme{Scheme: tpm20.TPMAlgNull},
		}),
	}
	validTPMSAttest = tpm20.TPMSAttest{
		Magic:           0xff544347,
		Type:            tpm20.TPMSTAttestCertify,
		QualifiedSigner: tpm20.TPM2BName{Buffer: []byte{0x0, 0xc, 0x35, 0xb9, 0x3b, 0xa2, 0xd6, 0x55, 0x96, 0x7, 0x80, 0xa7, 0x4, 0x48, 0x6b, 0xf, 0xd3, 0xce, 0xfb, 0xa9, 0x12, 0x49, 0x35, 0x7, 0xa1, 0xfc, 0x10, 0xae, 0xa9, 0x43, 0x82, 0xda, 0xd4, 0x72, 0x94, 0x97, 0xad, 0x55, 0xdf, 0x14, 0x78, 0x6d, 0xc4, 0x32, 0xc1, 0xb1, 0x9, 0x4d, 0xed, 0x3b}},
		ExtraData:       tpm20.TPM2BData{Buffer: []byte{}},
		ClockInfo:       tpm20.TPMSClockInfo{Clock: 0x3566eb68, ResetCount: 0x5d2, RestartCount: 0x0, Safe: true},
		FirmwareVersion: 0x1020000000000,
		Attested:        tpm20.NewTPMUAttest(tpm20.TPMSTAttestCertify, &tpm20.TPMSCertifyInfo{}),
	}

	validTPMTSignature = tpm20.TPMTSignature{
		SigAlg: tpm20.TPMAlgRSASSA,
	}
)

func binaryWriteUint32(buf *bytes.Buffer, value uint32) {
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		panic(fmt.Sprintf("failed to write uint32: %v", err))
	}
}

func binaryWriteUint16(buf *bytes.Buffer, value uint16) {
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		panic(fmt.Sprintf("failed to write uint16: %v", err))
	}
}

func ptrUint32(value uint32) *uint32 {
	return &value
}

func ptrString(value string) *string {
	return &value
}
