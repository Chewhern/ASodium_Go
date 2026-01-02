package sodiumshorthash

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetComputedHashLength() int {
	return int(C.crypto_shorthash_bytes())
}

func GetKeyLength() int {
	return int(C.crypto_shorthash_keybytes())
}

func GetSipHash24ComputedHashLength() int {
	return int(C.crypto_shorthash_siphashx24_bytes())
}

func GenerateShortHashKey() ([]byte, error) {
	key := make([]byte, GetKeyLength())

	C.crypto_shorthash_keygen(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	return key, nil
}

func GenerateShortHashKeyPtr() unsafe.Pointer {
	key, isZero := sodiumguardedheapallocation.SodiumMalloc(GetKeyLength())
	if isZero {
		return nil
	}

	C.crypto_shorthash_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	return key
}

func ComputeShortHash(
	message []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("message must not be null")
	}
	if key == nil || len(key) != GetKeyLength() {
		return nil, errors.New("invalid key length")
	}

	out := make([]byte, GetComputedHashLength())

	ret := C.crypto_shorthash(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("crypto_shorthash failed")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return out, nil
}

func ComputeShortHashPtr(
	message []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("message must not be null")
	}
	if key == nil {
		return nil, errors.New("key must not be null")
	}

	out := make([]byte, GetComputedHashLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_shorthash(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("crypto_shorthash failed")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return out, nil
}

func SipHash24ComputeHash(
	message []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("message must not be null")
	}
	if key == nil || len(key) != GetKeyLength() {
		return nil, errors.New("invalid key length")
	}

	out := make([]byte, GetSipHash24ComputedHashLength())

	ret := C.crypto_shorthash_siphashx24(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("siphashx24 failed")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return out, nil
}

func SipHash24ComputeHashPtr(
	message []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("message must not be null")
	}
	if key == nil {
		return nil, errors.New("key must not be null")
	}

	out := make([]byte, GetSipHash24ComputedHashLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_shorthash_siphashx24(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("siphashx24 failed")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return out, nil
}
