package sodiumgenerichash

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"fmt"
	"unsafe"
)

func GetStandardComputedHashLength() int {
	return int(C.crypto_generichash_bytes())
}

func GetMinComputedHashLength() int {
	return int(C.crypto_generichash_bytes_min())
}

func GetMaxComputedHashLength() int {
	return int(C.crypto_generichash_bytes_max())
}

func GetStandardKeyLength() int {
	return int(C.crypto_generichash_keybytes())
}

func GetMinKeyLength() int {
	return int(C.crypto_generichash_keybytes_min())
}

func GetMaxKeyLength() int {
	return int(C.crypto_generichash_keybytes_max())
}

func GetStateBytesLength() int {
	return int(C.crypto_generichash_statebytes())
}

func ComputeHashWithPtr(
	hashLen byte,
	message []byte,
	key unsafe.Pointer,
	keyLen int,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	if hashLen == 0 {
		return nil, fmt.Errorf("hash length cannot be 0")
	}

	hlen := int(hashLen)

	if hlen != GetStandardComputedHashLength() {
		if hlen < GetMinComputedHashLength() || hlen > GetMaxComputedHashLength() {
			return nil, fmt.Errorf(
				"hash length must be between %d and %d bytes",
				GetMinComputedHashLength(),
				GetMaxComputedHashLength(),
			)
		}
	}

	out := make([]byte, hlen)

	// No key → unkeyed hash
	if key == nil {
		return ComputeHash(hashLen, message, nil, false)
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	rc := C.crypto_generichash(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(key),
		C.size_t(keyLen),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to compute hash")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return out, nil
}

func ComputeHash(
	hashLen byte,
	message []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	if hashLen == 0 {
		return nil, fmt.Errorf("hash length cannot be 0")
	}

	hlen := int(hashLen)

	if hlen != GetStandardComputedHashLength() {
		if hlen < GetMinComputedHashLength() || hlen > GetMaxComputedHashLength() {
			return nil, fmt.Errorf(
				"hash length must be between %d and %d bytes",
				GetMinComputedHashLength(),
				GetMaxComputedHashLength(),
			)
		}
	}

	if key != nil {
		if len(key) != GetStandardKeyLength() {
			if len(key) < GetMinKeyLength() || len(key) > GetMaxKeyLength() {
				return nil, fmt.Errorf(
					"key length must be between %d and %d bytes",
					GetMinKeyLength(),
					GetMaxKeyLength(),
				)
			}
		}
	}

	out := make([]byte, hlen)

	var keyPtr *C.uchar
	var keyLen C.size_t

	if key != nil {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
		keyLen = C.size_t(len(key))
	}

	rc := C.crypto_generichash(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		keyPtr,
		keyLen,
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to compute hash")
	}

	if clearKey && key != nil {
		sodiumsecurememory.MemZero(key)
	}

	return out, nil
}

func GenerateStandardKey() []byte {
	key := make([]byte, GetStandardKeyLength())
	C.crypto_generichash_keygen(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)
	return key
}

func GenerateStandardKeyPtr() unsafe.Pointer {
	var isZero bool
	var key unsafe.Pointer

	key, isZero = sodiumguardedheapallocation.SodiumMalloc(GetStandardKeyLength())

	tries := 0
	for tries < 5 && isZero == true {
		key, isZero = sodiumguardedheapallocation.SodiumMalloc(GetStandardKeyLength())
		if isZero == false {
			break
		}
		tries += 1
	}

	if isZero == false {
		C.crypto_generichash_keygen((*C.uchar)(key))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
		return key
	} else {
		return nil
	}
}

func GenerateMinKey() []byte {
	return sodiumrng.GetRandomBytes(GetMinKeyLength())
}

func GenerateMaxKey() []byte {
	return sodiumrng.GetRandomBytes(GetMaxKeyLength())
}

func GenerateMinKeyPtr() unsafe.Pointer {
	return sodiumrng.GetRandomBytesPtr(GetMinKeyLength())
}

func GenerateMaxKeyPtr() unsafe.Pointer {
	return sodiumrng.GetRandomBytesPtr(GetMaxKeyLength())
}

func InitializeState(
	key []byte,
	outLen byte,
	clearKey bool,
) ([]byte, error) {

	if outLen == 0 {
		return nil, fmt.Errorf("out length cannot be 0")
	}

	ol := int(outLen)
	if ol != GetStandardComputedHashLength() {
		if ol < GetMinComputedHashLength() || ol > GetMaxComputedHashLength() {
			return nil, fmt.Errorf("invalid output length")
		}
	}

	if key != nil {
		if len(key) != GetStandardKeyLength() {
			if len(key) < GetMinKeyLength() || len(key) > GetMaxKeyLength() {
				return nil, fmt.Errorf("invalid key length")
			}
		}
	}

	state := make([]byte, GetStateBytesLength())

	var keyPtr *C.uchar
	var keyLen C.size_t
	if key != nil {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
		keyLen = C.size_t(len(key))
	}

	rc := C.crypto_generichash_init(
		(*C.crypto_generichash_state)(unsafe.Pointer(&state[0])),
		keyPtr,
		keyLen,
		C.size_t(outLen),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to initialize state")
	}

	if clearKey && key != nil {
		sodiumsecurememory.MemZero(key)
	}

	return state, nil
}

func InitializeStatePtr(
	key unsafe.Pointer,
	keyLen int,
	outLen byte,
	clearKey bool,
) (unsafe.Pointer, error) {

	if outLen == 0 {
		return nil, fmt.Errorf("out length cannot be 0")
	}

	ol := int(outLen)
	if ol != GetStandardComputedHashLength() {
		if ol < GetMinComputedHashLength() || ol > GetMaxComputedHashLength() {
			return nil, fmt.Errorf("invalid output length")
		}
	}

	if key != nil {
		if keyLen < GetMinKeyLength() || keyLen > GetMaxKeyLength() {
			return nil, fmt.Errorf("invalid key length")
		}
	}

	state, isZero := sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())

	tries := 0
	for tries < 5 && isZero == true {
		state, isZero = sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())
		if isZero == false {
			break
		}
		tries += 1
	}

	if isZero == false && tries < 5 {
		if outLen != 0 {
			if outLen != byte(GetStandardComputedHashLength()) {
				if outLen >= byte(GetMinComputedHashLength()) && outLen < byte(GetMaxComputedHashLength()) == false {
					return nil, nil
				}
			}
		}
	}

	rc := C.crypto_generichash_init(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(key),
		C.size_t(keyLen),
		C.size_t(outLen),
	)

	if rc != 0 {
		sodiumguardedheapallocation.SodiumFree(state)
		return nil, nil
	}

	if clearKey && key != nil {
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return state, nil
}

func UpdateState(state []byte, message []byte) ([]byte, error) {
	if state == nil || len(state) != GetStateBytesLength() {
		return nil, fmt.Errorf("invalid state")
	}
	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	rc := C.crypto_generichash_update(
		(*C.crypto_generichash_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to update state")
	}

	return state, nil
}

func UpdateStatePtr(state unsafe.Pointer, message []byte) unsafe.Pointer {
	if state == nil || message == nil {
		return nil
	}

	rc := C.crypto_generichash_update(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
	)

	if rc != 0 {
		return nil
	}

	return state
}

func ComputeHashForFinalizedState(
	state []byte,
	hashLen byte,
) ([]byte, error) {

	if state == nil {
		return nil, fmt.Errorf("state cannot be nil")
	}
	if len(state) != GetStateBytesLength() {
		return nil, fmt.Errorf(
			"state must be %d bytes",
			GetStateBytesLength(),
		)
	}

	if hashLen == 0 {
		return nil, fmt.Errorf("hash length cannot be 0")
	}

	hl := int(hashLen)
	if hl != GetStandardComputedHashLength() {
		if hl < GetMinComputedHashLength() || hl > GetMaxComputedHashLength() {
			return nil, fmt.Errorf("invalid hash length")
		}
	}

	out := make([]byte, hashLen)

	rc := C.crypto_generichash_final(
		(*C.crypto_generichash_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(hashLen),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to finalize hash")
	}

	return out, nil
}

func ComputeHashForFinalizedStatePtr(
	state unsafe.Pointer,
	hashLen byte,
) ([]byte, error) {

	if state == nil {
		return nil, fmt.Errorf("state cannot be nil")
	}

	if hashLen == 0 {
		return nil, fmt.Errorf("hash length cannot be 0")
	}

	hl := int(hashLen)
	if hl != GetStandardComputedHashLength() {
		if hl < GetMinComputedHashLength() || hl > GetMaxComputedHashLength() {
			return nil, fmt.Errorf("invalid hash length")
		}
	}

	out := make([]byte, hashLen)

	rc := C.crypto_generichash_final(
		(*C.crypto_generichash_state)(state),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(hashLen),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to finalize hash")
	}

	return out, nil
}
