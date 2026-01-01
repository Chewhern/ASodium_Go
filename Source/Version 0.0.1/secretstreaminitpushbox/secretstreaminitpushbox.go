package secretstreaminitpushbox

import "unsafe"

// SecretStreamInitPushBox mirrors the C# SecretStreamInitPushBox
type SecretStreamInitPushBox struct {
	StateByte  []byte
	HeaderByte []byte

	StatePtr  unsafe.Pointer
	HeaderPtr unsafe.Pointer
}
