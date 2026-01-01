package sodiumonetimeauth

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetStateBytesLength() int {
	return int(C.crypto_onetimeauth_statebytes())
}

func GetPoly1305MACLength() int {
	return int(C.crypto_onetimeauth_bytes())
}

func GetKeyBytesLength() int {
	return int(C.crypto_onetimeauth_keybytes())
}

func GenerateKey() []byte {
	key := make([]byte, GetKeyBytesLength())
	C.crypto_onetimeauth_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func GenerateKeyPtr() unsafe.Pointer {

	key, isZero := sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())
	if isZero == true || key == nil {
		return nil
	}

	C.crypto_onetimeauth_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	return key
}

func ComputePoly1305MAC(
	message []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}
	if len(key) != GetKeyBytesLength() {
		return nil, errors.New("invalid key length")
	}

	mac := make([]byte, GetPoly1305MACLength())

	ret := C.crypto_onetimeauth(
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	if ret != 0 {
		return nil, errors.New("failed to compute Poly1305 MAC")
	}

	return mac, nil
}

func ComputePoly1305MACPtr(
	message []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}
	if key == nil {
		return nil, errors.New("key must not be null")
	}

	mac := make([]byte, GetPoly1305MACLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_onetimeauth(
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	if ret != 0 {
		return nil, errors.New("failed to compute Poly1305 MAC")
	}

	return mac, nil
}

func VerifyPoly1305MAC(
	mac []byte,
	message []byte,
	key []byte,
	clearKey bool,
) (bool, error) {

	if len(message) == 0 {
		return false, errors.New("message must not be empty")
	}
	if len(key) != GetKeyBytesLength() {
		return false, errors.New("invalid key length")
	}
	if len(mac) != GetPoly1305MACLength() {
		return false, errors.New("invalid mac length")
	}

	ret := C.crypto_onetimeauth_verify(
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return ret == 0, nil
}

func VerifyPoly1305MACPtr(
	mac []byte,
	message []byte,
	key unsafe.Pointer,
	clearKey bool,
) (bool, error) {

	if len(message) == 0 {
		return false, errors.New("message must not be empty")
	}
	if key == nil {
		return false, errors.New("key must not be null")
	}
	if len(mac) != GetPoly1305MACLength() {
		return false, errors.New("invalid mac length")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_onetimeauth_verify(
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
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

func InitializeState(key []byte, clearKey bool) ([]byte, error) {
	if key == nil {
		return nil, errors.New("key must not be nil")
	}
	if len(key) != GetKeyBytesLength() {
		return nil, errors.New("invalid key length")
	}

	state := make([]byte, GetStateBytesLength())

	ret := C.crypto_onetimeauth_init(
		(*C.crypto_onetimeauth_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("failed to initialize poly1305 state")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return state, nil
}

func InitializeStatePtr(key unsafe.Pointer, clearKey bool) (unsafe.Pointer, error) {
	if key == nil {
		return nil, errors.New("key must not be nil")
	}

	state, isZero := sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())
	if isZero == true || state == nil {
		return nil, errors.New("sodium_malloc failed")
	}

	ret := C.crypto_onetimeauth_init(
		(*C.crypto_onetimeauth_state)(state),
		(*C.uchar)(key),
	)

	if ret != 0 {
		sodiumguardedheapallocation.SodiumFree(state)
		return nil, errors.New("failed to initialize poly1305 state")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)
	return state, nil
}

func UpdateState(state []byte, message []byte) ([]byte, error) {
	if state == nil || len(state) != GetStateBytesLength() {
		return nil, errors.New("invalid state")
	}
	if message == nil || len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}

	ret := C.crypto_onetimeauth_update(
		(*C.crypto_onetimeauth_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
	)

	if ret != 0 {
		return nil, errors.New("failed to update poly1305 state")
	}

	return state, nil
}

func UpdateStatePtr(state unsafe.Pointer, message []byte) (unsafe.Pointer, error) {
	if state == nil {
		return nil, errors.New("state must not be nil")
	}
	if message == nil || len(message) == 0 {
		return nil, errors.New("message must not be empty")
	}

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)

	ret := C.crypto_onetimeauth_update(
		(*C.crypto_onetimeauth_state)(state),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if ret != 0 {
		return nil, errors.New("failed to update poly1305 state")
	}

	return state, nil
}

func ComputeFinalizedStatePoly1305MAC(state []byte, clearState bool) ([]byte, error) {
	if state == nil || len(state) != GetStateBytesLength() {
		return nil, errors.New("invalid state")
	}

	mac := make([]byte, GetPoly1305MACLength())

	ret := C.crypto_onetimeauth_final(
		(*C.crypto_onetimeauth_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
	)

	if ret != 0 {
		return nil, errors.New("failed to finalize poly1305 MAC")
	}

	if clearState {
		sodiumsecurememory.MemZero(state)
	}

	return mac, nil
}

func ComputeFinalizedStatePoly1305MACPtr(state unsafe.Pointer, clearState bool) ([]byte, error) {
	if state == nil {
		return nil, errors.New("state must not be nil")
	}

	mac := make([]byte, GetPoly1305MACLength())

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)

	ret := C.crypto_onetimeauth_final(
		(*C.crypto_onetimeauth_state)(state),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if ret != 0 {
		return nil, errors.New("failed to finalize poly1305 MAC")
	}

	if clearState {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
	}

	return mac, nil
}
