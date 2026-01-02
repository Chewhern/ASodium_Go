package sodiumsealedpublickeybox

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumpublickeybox"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetSealBytes() int {
	return int(C.crypto_box_sealbytes())
}

func SealedBoxCreate(
	message []byte,
	otherUserPublicKey []byte,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}

	if otherUserPublicKey == nil {
		return nil, errors.New("Error: Public Key cannot be null")
	}
	if len(otherUserPublicKey) != sodiumpublickeybox.GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length invalid")
	}

	cipherText := make([]byte, len(message)+GetSealBytes())

	ret := C.crypto_box_seal(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to create Sealed Box")
	}

	return cipherText, nil
}

func SealedBoxOpen(
	cipherText []byte,
	currentUserPublicKey []byte,
	currentUserSecretKey []byte,
	clearKey bool,
) ([]byte, error) {

	if cipherText == nil {
		return nil, errors.New("Error: Cipher Text cannot be null")
	}
	if len(cipherText)-GetSealBytes() <= 0 {
		return nil, errors.New("Error: Cipher Text malformed")
	}

	if currentUserPublicKey == nil {
		return nil, errors.New("Error: Public Key cannot be null")
	}
	if len(currentUserPublicKey) != sodiumpublickeybox.GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length invalid")
	}

	if currentUserSecretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}
	if len(currentUserSecretKey) != sodiumpublickeybox.GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret key length invalid")
	}

	message := make([]byte, len(cipherText)-GetSealBytes())

	ret := C.crypto_box_seal_open(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&currentUserPublicKey[0])),
		(*C.uchar)(unsafe.Pointer(&currentUserSecretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to open sealed box")
	}

	if clearKey {
		sodiumsecurememory.MemZero(currentUserSecretKey)
	}

	return message, nil
}

func SealedBoxOpenPtr(
	cipherText []byte,
	currentUserPublicKey []byte,
	currentUserSecretKey unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if cipherText == nil {
		return nil, errors.New("Error: Cipher Text cannot be null")
	}
	if len(cipherText)-GetSealBytes() <= 0 {
		return nil, errors.New("Error: Cipher Text malformed")
	}

	if currentUserPublicKey == nil {
		return nil, errors.New("Error: Public Key cannot be null")
	}
	if len(currentUserPublicKey) != sodiumpublickeybox.GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length invalid")
	}

	if currentUserSecretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}

	message := make([]byte, len(cipherText)-GetSealBytes())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentUserSecretKey)

	ret := C.crypto_box_seal_open(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&currentUserPublicKey[0])),
		(*C.uchar)(currentUserSecretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentUserSecretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to open sealed box")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentUserSecretKey)
		sodiumguardedheapallocation.SodiumFree(currentUserSecretKey)
	}

	return message, nil
}
