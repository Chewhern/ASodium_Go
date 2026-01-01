package sodiumhmacsha512

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"fmt"
	"unsafe"
)

func GetKeyBytesLength() int {
	return int(C.crypto_auth_hmacsha512_keybytes())
}

func GetComputedMACLength() int {
	return int(C.crypto_auth_hmacsha512_bytes())
}

func GenerateKey() []byte {
	key := make([]byte, GetKeyBytesLength())
	C.crypto_auth_hmacsha512_keygen((*C.uchar)(&key[0]))
	return key
}

func GenerateKeyIntPtr() unsafe.Pointer {
	var key unsafe.Pointer
	isZero := true
	key, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())

	tryAttempts := 5
	count := 0

	for isZero == true && count < tryAttempts {
		key, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())
		count++
	}

	if isZero == false && count < tryAttempts {
		C.crypto_auth_hmacsha512_keygen((*C.uchar)(key))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
		return key
	}

	return nil
}

func ComputeMAC(message, key []byte, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("message must not be nil")
	}
	if key == nil || len(key) != GetKeyBytesLength() {
		return nil, fmt.Errorf("invalid key length")
	}

	mac := make([]byte, GetComputedMACLength())

	ret := C.crypto_auth_hmacsha512(
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&key[0]),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	if ret != 0 {
		return nil, fmt.Errorf("failed to compute MAC")
	}

	return mac, nil
}

func ComputeMACWithPtr(message []byte, key unsafe.Pointer, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("message must not be nil")
	}
	if key == nil {
		return nil, fmt.Errorf("key must not be nil")
	}

	mac := make([]byte, GetComputedMACLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_auth_hmacsha512(
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	if ret != 0 {
		return nil, fmt.Errorf("failed to compute MAC")
	}

	return mac, nil
}

func VerifyMAC(mac, message, key []byte, clearKey bool) (bool, error) {
	if message == nil {
		return false, fmt.Errorf("message must not be nil")
	}
	if key == nil || len(key) != GetKeyBytesLength() {
		return false, fmt.Errorf("invalid key length")
	}
	if mac == nil || len(mac) != GetComputedMACLength() {
		return false, fmt.Errorf("invalid MAC length")
	}

	ret := C.crypto_auth_hmacsha512_verify(
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&key[0]),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return ret == 0, nil
}

func VerifyMACWithPtr(mac, message []byte, key unsafe.Pointer, clearKey bool) (bool, error) {
	if message == nil {
		return false, fmt.Errorf("message must not be nil")
	}
	if key == nil {
		return false, fmt.Errorf("key must not be nil")
	}
	if mac == nil || len(mac) != GetComputedMACLength() {
		return false, fmt.Errorf("invalid MAC length")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_auth_hmacsha512_verify(
		(*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return ret == 0, nil
}
