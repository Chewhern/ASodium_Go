package sodiumsecretboxxchacha20poly1305

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/detachedbox"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetKeyBytesLength() int {
	return int(C.crypto_secretbox_xchacha20poly1305_keybytes())
}

func GetNonceBytesLength() int {
	return int(C.crypto_secretbox_xchacha20poly1305_noncebytes())
}

func GetMACBytesLength() int {
	return int(C.crypto_secretbox_xchacha20poly1305_macbytes())
}

func GenerateKey() []byte {
	return sodiumrng.GetRandomBytes(GetKeyBytesLength())
}

func GenerateKeyIntPtr() unsafe.Pointer {
	key := sodiumrng.GetRandomBytesPtr(GetKeyBytesLength())
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
	return key
}

func GenerateNonce() []byte {
	return sodiumrng.GetRandomBytes(GetNonceBytesLength())
}

func Create(message, nonce, key []byte, clearKey bool) ([]byte, error) {
	if len(key) != GetKeyBytesLength() {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length is not the same")
	}

	cipherText := make([]byte, GetMACBytesLength()+len(message))

	rc := C.crypto_secretbox_xchacha20poly1305_easy(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if rc != 0 {
		return nil, errors.New("Failed to create SecretBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return cipherText, nil
}

func CreateWithPtr(message, nonce []byte, key unsafe.Pointer, clearKey bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Error: Key must not be null/empty")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, GetMACBytesLength()+len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_xchacha20poly1305_easy(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if rc != 0 {
		return nil, errors.New("Failed to create SecretBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return cipherText, nil
}

func Open(cipherText, nonce, key []byte, clearKey bool) ([]byte, error) {
	if len(key) != GetKeyBytesLength() {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	message := make([]byte, len(cipherText)-GetMACBytesLength())

	rc := C.crypto_secretbox_xchacha20poly1305_open_easy(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if rc != 0 {
		return nil, errors.New("Failed to open SecretBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return message, nil
}

func OpenWithPtr(cipherText, nonce []byte, key unsafe.Pointer, clearKey bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("Error: Key must not be null/empty")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	message := make([]byte, len(cipherText)-GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_xchacha20poly1305_open_easy(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if rc != 0 {
		return nil, errors.New("Failed to open SecretBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return message, nil
}

func CreateDetached(message, nonce, key []byte, clearKey bool) (*detachedbox.DetachedBox, error) {
	if len(key) != GetKeyBytesLength() {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, GetNonceBytesLength())

	rc := C.crypto_secretbox_xchacha20poly1305_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if rc != 0 {
		return nil, errors.New("Failed to create detached SecretBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func CreateDetachedWithPtr(message, nonce []byte, key unsafe.Pointer, clearKey bool) (*detachedbox.DetachedBox, error) {
	if key == nil {
		return nil, errors.New("Error: Key must not be null/empty")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_xchacha20poly1305_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if rc != 0 {
		return nil, errors.New("Failed to create detached SecretBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func OpenDetachedFromBox(
	detached *detachedbox.DetachedBox,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return OpenDetached(
		detached.CipherText,
		detached.Mac,
		nonce,
		key,
		clearKey,
	)
}

func OpenDetachedFromBoxPtr(
	detached *detachedbox.DetachedBox,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return OpenDetachedPtr(
		detached.CipherText,
		detached.Mac,
		nonce,
		key,
		clearKey,
	)
}

func OpenDetached(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != GetKeyBytesLength() {
		return nil, errors.New("Error: Key must be 32 bytes in length.")
	}
	if nonce == nil || len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length is not the same.")
	}
	if mac == nil || len(mac) != GetMACBytesLength() {
		return nil, errors.New("Error: MAC length is not the same.")
	}

	message := make([]byte, len(cipherText))

	result := C.crypto_secretbox_xchacha20poly1305_open_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	if result != 0 {
		return nil, errors.New("Failed to open detached SecretBox")
	}

	return message, nil
}

func OpenDetachedPtr(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if key == nil {
		return nil, errors.New("Error: Key must not be null/empty")
	}
	if nonce == nil || len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be 24 bytes in length.")
	}
	if mac == nil || len(mac) != GetMACBytesLength() {
		return nil, errors.New("Error: MAC must be 16 bytes in length.")
	}

	message := make([]byte, len(cipherText))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	result := C.crypto_secretbox_xchacha20poly1305_open_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if result != 0 {
		return nil, errors.New("Failed to open detached SecretBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return message, nil
}
