package sodiumsecretkeyauth

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetMACLength() int {
	return int(C.crypto_auth_bytes())
}

func GetKeyLength() int {
	return int(C.crypto_auth_keybytes())
}

func GenKey() []byte {
	key := make([]byte, GetKeyLength())
	C.crypto_auth_keygen((*C.uchar)(&key[0]))
	return key
}

func GenKeyIntPtr() unsafe.Pointer {
	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetKeyLength())
	if !isZero {
		C.crypto_auth_keygen((*C.uchar)(keyPtr))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	} else {
		keyPtr = nil
	}
	return keyPtr
}

func Sign(message, key []byte, clearKey bool) ([]byte, error) {
	if len(key) != GetKeyLength() {
		return nil, errors.New("key length is invalid")
	}
	mac := make([]byte, GetMACLength())
	C.crypto_auth((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&key[0]))
	if clearKey {
		sodiumsecurememory.MemZero(key)
	}
	return mac, nil
}

func SignPtr(message []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if keyPtr == nil {
		return nil, errors.New("key pointer is nil")
	}
	mac := make([]byte, GetMACLength())
	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	C.crypto_auth((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(keyPtr))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}
	return mac, nil
}

func Verify(message, mac, key []byte, clearKey bool) error {
	if len(key) != GetKeyLength() {
		return errors.New("key length is invalid")
	}
	if len(mac) != GetMACLength() {
		return errors.New("MAC length is invalid")
	}
	ret := C.crypto_auth_verify((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&key[0]))
	if clearKey {
		sodiumsecurememory.MemZero(key)
	}
	if ret != 0 {
		return errors.New("MAC does not match message")
	}
	return nil
}

func VerifyPtr(message, mac []byte, keyPtr unsafe.Pointer, clearKey bool) error {
	if keyPtr == nil {
		return errors.New("key pointer is nil")
	}
	if len(mac) != GetMACLength() {
		return errors.New("MAC length is invalid")
	}
	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	ret := C.crypto_auth_verify((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(keyPtr))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}
	if ret != 0 {
		return errors.New("MAC does not match message")
	}
	return nil
}

func VerifyMAC(message, mac, key []byte, clearKey bool) bool {
	if len(key) != GetKeyLength() || len(mac) != GetMACLength() {
		return false
	}
	ret := C.crypto_auth_verify((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&key[0]))
	if clearKey {
		sodiumsecurememory.MemZero(key)
	}
	return ret == 0
}

func VerifyMACPtr(message, mac []byte, keyPtr unsafe.Pointer, clearKey bool) bool {
	if keyPtr == nil || len(mac) != GetMACLength() {
		return false
	}
	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	ret := C.crypto_auth_verify((*C.uchar)(&mac[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(keyPtr))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}
	return ret == 0
}
