package sodiumkeyexchangesharedsecretpointerbox

import "unsafe"

type SodiumKeyExchangeSharedSecretPointerBox struct {
	ReadSharedSecret     unsafe.Pointer
	TransferSharedSecret unsafe.Pointer

	ReadSharedSecretLength     int
	TransferSharedSecretLength int
}
