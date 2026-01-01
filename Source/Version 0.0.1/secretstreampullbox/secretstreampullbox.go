package secretstreampullbox

import "unsafe"

// SecretStreamPullBox mirrors the C# SecretStreamPullBox
type SecretStreamPullBox struct {
	StateByte []byte
	StatePtr  unsafe.Pointer

	CipherText    []byte
	MessageLength int64

	TagByte byte

	MessageByte    []byte
	AdditionalData []byte
}
