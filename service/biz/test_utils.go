package biz

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func binaryWriteUint32(buf *bytes.Buffer, value uint32) {
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		panic(fmt.Sprintf("failed to write uint32: %v", err))
	}
}

func ptrUint32(value uint32) *uint32 {
	return &value
}

func ptrString(value string) *string {
	return &value
}
