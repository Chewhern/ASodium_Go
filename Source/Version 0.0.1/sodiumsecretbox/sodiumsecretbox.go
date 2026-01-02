package sodiumsecretbox

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

const (
	INT_KEY_BYTES   = 32
	INT_NONCE_BYTES = 24
	MAC_BYTES       = 16
	INT_MAC_BYTES   = 16
)

func GenerateKey() []byte {
	key := make([]byte, INT_KEY_BYTES)
	C.crypto_secretbox_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func GenerateKeyIntPtr() unsafe.Pointer {
	key, isZero := sodiumguardedheapallocation.SodiumMalloc(INT_KEY_BYTES)
	if !isZero {
		C.crypto_secretbox_keygen((*C.uchar)(key))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
		return key
	}
	return nil
}

func GenerateNonce() []byte {
	return sodiumrng.GetRandomBytes(INT_NONCE_BYTES)
}

func Create(message, nonce, key []byte, clearKey bool) ([]byte, error) {
	if len(key) != INT_KEY_BYTES {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, INT_MAC_BYTES+len(message))

	rc := C.crypto_secretbox_easy(
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
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, INT_MAC_BYTES+len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_easy(
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
	if len(key) != INT_KEY_BYTES {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	message := make([]byte, len(cipherText)-INT_MAC_BYTES)

	rc := C.crypto_secretbox_open_easy(
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
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	message := make([]byte, len(cipherText)-INT_MAC_BYTES)

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_open_easy(
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
	if len(key) != INT_KEY_BYTES {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, MAC_BYTES)

	rc := C.crypto_secretbox_detached(
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
	if len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, MAC_BYTES)

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	rc := C.crypto_secretbox_detached(
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

	if key == nil || len(key) != INT_KEY_BYTES {
		return nil, errors.New("Error: Key must be 32 bytes in length.")
	}
	if nonce == nil || len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length.")
	}
	if mac == nil || len(mac) != INT_MAC_BYTES {
		return nil, errors.New("Error: MAC must be 16 bytes in length.")
	}

	message := make([]byte, len(cipherText))

	result := C.crypto_secretbox_open_detached(
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
	if nonce == nil || len(nonce) != INT_NONCE_BYTES {
		return nil, errors.New("Error: Nonce must be 24 bytes in length.")
	}
	if mac == nil || len(mac) != INT_MAC_BYTES {
		return nil, errors.New("Error: MAC must be 16 bytes in length.")
	}

	message := make([]byte, len(cipherText))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	result := C.crypto_secretbox_open_detached(
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
