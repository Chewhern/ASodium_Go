package secretstreampushbox

import "unsafe"

// SecretStreamPushBox mirrors the C# SecretStreamPushBox
type SecretStreamPushBox struct {
	StateByte []byte
	StatePtr  unsafe.Pointer

	CipherText       []byte
	CipherTextLength int64

	MessageByte    []byte
	AdditionalData []byte
}
