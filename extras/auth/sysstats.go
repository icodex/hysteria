package auth

import (
	"bytes"
	"encoding/json"
	"io"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func stringsReader(b []byte) io.Reader  { return bytes.NewReader(b) }

// memInfo 内存/交换分区用量（字节）
type memInfo struct {
	total, used         uint64
	swapTotal, swapUsed uint64
}
