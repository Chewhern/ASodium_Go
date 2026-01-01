package sodiumhkdfsha256

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetKeyBytesLength() int {
	return int(C.crypto_kdf_hkdf_sha256_keybytes())
}

func GetMinDerivedKeyBytesLength() int {
	return int(C.crypto_kdf_hkdf_sha256_bytes_min())
}

func GetMaxDerivedKeyBytesLength() int {
	return int(C.crypto_kdf_hkdf_sha256_bytes_max())
}

func GetStateBytesLength() int {
	return int(C.crypto_kdf_hkdf_sha256_statebytes())
}

//
// Generate key into Go-managed memory ([]byte)
//

func GenerateKey() []byte {
	keyLen := GetKeyBytesLength()
	key := make([]byte, keyLen)

	// libsodium fills the buffer
	C.crypto_kdf_hkdf_sha256_keygen(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	return key
}

//
// Generate key into libsodium guarded heap (unsafe.Pointer)
//

func GenerateKeyPtr() unsafe.Pointer {
	keyLen := GetKeyBytesLength()
	var ptr unsafe.Pointer
	var i int = 0
	var isZero bool

	const maxAttempts = 5
	ptr, isZero = sodiumguardedheapallocation.SodiumMalloc(keyLen)
	for i < maxAttempts && isZero == true {
		ptr, isZero = sodiumguardedheapallocation.SodiumMalloc(keyLen)

		i += 1
	}

	if isZero == false {
		// libsodium guarantees non-zeroed random keygen
		C.crypto_kdf_hkdf_sha256_keygen((*C.uchar)(ptr))

		// protect memory (read-only or no-access depending on your model)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(ptr)
	} else {
		ptr = nil
	}
	return ptr
}

func GenerateOptionalSalt(length int) []byte {
	if length <= 0 {
		length = 32
	}
	return sodiumrng.GetRandomBytes(length)
}

func Expand(
	derivedKeyLength int,
	context string,
	masterKey []byte,
	clearKey bool,
) []byte {
	return ExpandWithContextBytes(
		derivedKeyLength,
		[]byte(context),
		masterKey,
		clearKey,
	)
}

func ExpandWithContextBytes(
	derivedKeyLength int,
	context []byte,
	masterKey []byte,
	clearKey bool,
) []byte {

	if derivedKeyLength < GetMinDerivedKeyBytesLength() {
		panic("Error: Derived key length is too small")
	}
	if derivedKeyLength > GetMaxDerivedKeyBytesLength() {
		panic("Error: Derived key length is too large")
	}
	if masterKey == nil {
		panic("Error: Master key must not be nil")
	}
	if len(masterKey) != GetKeyBytesLength() {
		panic("Error: Master key length mismatch")
	}

	derivedKey := make([]byte, derivedKeyLength)

	var ctxPtr unsafe.Pointer
	var ctxLen C.size_t

	if context != nil && len(context) > 0 {
		ctxPtr = unsafe.Pointer(&context[0])
		ctxLen = C.size_t(len(context))
	}

	C.crypto_kdf_hkdf_sha256_expand(
		(*C.uchar)(unsafe.Pointer(&derivedKey[0])),
		C.size_t(derivedKeyLength),
		(*C.char)(ctxPtr),
		ctxLen,
		(*C.uchar)(unsafe.Pointer(&masterKey[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(masterKey)
	}

	return derivedKey
}

func ExpandPtr(
	derivedKeyLength int,
	context string,
	masterKey unsafe.Pointer,
	clearKey bool,
) unsafe.Pointer {
	return ExpandPtrWithContextBytes(
		derivedKeyLength,
		[]byte(context),
		masterKey,
		clearKey,
	)
}

func ExpandPtrWithContextBytes(
	derivedKeyLength int,
	context []byte,
	masterKey unsafe.Pointer,
	clearKey bool,
) unsafe.Pointer {

	if derivedKeyLength < GetMinDerivedKeyBytesLength() {
		panic("Error: Derived key length is too small")
	}
	if derivedKeyLength > GetMaxDerivedKeyBytesLength() {
		panic("Error: Derived key length is too large")
	}
	if masterKey == nil {
		panic("Error: Master key must not be nil")
	}

	isZero := true
	var derivedKey unsafe.Pointer
	derivedKey, isZero = sodiumguardedheapallocation.SodiumMalloc(derivedKeyLength)

	tryAttempts := 5
	count := 0

	for isZero == true && count < tryAttempts {
		derivedKey, isZero = sodiumguardedheapallocation.SodiumMalloc(derivedKeyLength)
		count++
	}

	if isZero || count >= tryAttempts {
		return nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(masterKey)

	var ctxPtr unsafe.Pointer
	var ctxLen C.size_t

	if context != nil && len(context) > 0 {
		ctxPtr = unsafe.Pointer(&context[0])
		ctxLen = C.size_t(len(context))
	}

	C.crypto_kdf_hkdf_sha256_expand(
		(*C.uchar)(derivedKey),
		C.size_t(derivedKeyLength),
		(*C.char)(ctxPtr),
		ctxLen,
		(*C.uchar)(masterKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(derivedKey)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(masterKey)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(masterKey)
		sodiumguardedheapallocation.SodiumFree(masterKey)
	}

	return derivedKey
}

func Extract(salt []byte, ikm []byte, clearKey bool) []byte {
	if ikm == nil || len(ikm) == 0 {
		panic("Error: Input key material can't be null or empty")
	}

	masterKey := make([]byte, GetKeyBytesLength())

	if salt == nil {
		C.crypto_kdf_hkdf_sha256_extract(
			(*C.uchar)(&masterKey[0]),
			nil,
			0,
			(*C.uchar)(&ikm[0]),
			C.size_t(len(ikm)),
		)
	} else {
		C.crypto_kdf_hkdf_sha256_extract(
			(*C.uchar)(&masterKey[0]),
			(*C.uchar)(&salt[0]),
			C.size_t(len(salt)),
			(*C.uchar)(&ikm[0]),
			C.size_t(len(ikm)),
		)
	}

	if clearKey {
		sodiumsecurememory.MemZero(ikm)
	}

	return masterKey
}

func ExtractPtr(
	salt []byte,
	ikmPtr unsafe.Pointer,
	ikmLen int64,
	clearKey bool,
) unsafe.Pointer {

	if ikmPtr == nil {
		panic("Error: Input key material can't be null")
	}

	var masterKey unsafe.Pointer
	isZero := true
	masterKey, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())

	const maxTry = 5
	tries := 0
	for isZero == true && tries < maxTry {
		masterKey, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())
		tries++
	}

	if isZero == false && tries < maxTry {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(ikmPtr)

		if salt == nil {
			C.crypto_kdf_hkdf_sha256_extract(
				(*C.uchar)(masterKey),
				nil,
				0,
				(*C.uchar)(ikmPtr),
				C.size_t(ikmLen),
			)
		} else {
			C.crypto_kdf_hkdf_sha256_extract(
				(*C.uchar)(masterKey),
				(*C.uchar)(&salt[0]),
				C.size_t(len(salt)),
				(*C.uchar)(ikmPtr),
				C.size_t(ikmLen),
			)
		}

		sodiumguardedheapallocation.SodiumMProtectNoAccess(masterKey)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(ikmPtr)
	} else {
		masterKey = nil
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(ikmPtr)
		sodiumguardedheapallocation.SodiumFree(ikmPtr)
	}

	return masterKey
}

func StateInitialization(salt []byte) ([]byte, error) {
	state := make([]byte, GetStateBytesLength())

	if salt == nil {
		if C.crypto_kdf_hkdf_sha256_extract_init(
			(*C.crypto_kdf_hkdf_sha256_state)(unsafe.Pointer(&state[0])),
			nil,
			0,
		) != 0 {
			return nil, errors.New("hkdf extract init failed")
		}
	} else {
		if C.crypto_kdf_hkdf_sha256_extract_init(
			(*C.crypto_kdf_hkdf_sha256_state)(unsafe.Pointer(&state[0])),
			(*C.uchar)(unsafe.Pointer(&salt[0])),
			C.size_t(len(salt)),
		) != 0 {
			return nil, errors.New("hkdf extract init failed")
		}
	}

	return state, nil
}

func StateUpdate(state []byte, ikm []byte, clearKey bool) ([]byte, error) {
	if len(state) != GetStateBytesLength() {
		return nil, errors.New("invalid state length")
	}
	if len(ikm) == 0 {
		return nil, errors.New("ikm must not be empty")
	}

	if C.crypto_kdf_hkdf_sha256_extract_update(
		(*C.crypto_kdf_hkdf_sha256_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&ikm[0])),
		C.size_t(len(ikm)),
	) != 0 {
		return nil, errors.New("hkdf extract update failed")
	}

	if clearKey {
		sodiumsecurememory.MemZero(ikm)
	}

	return state, nil
}

func ExtractMasterKeyFromFinalState(state []byte, clearState bool) ([]byte, error) {
	if len(state) != GetStateBytesLength() {
		return nil, errors.New("invalid state length")
	}

	masterKey := make([]byte, GetKeyBytesLength())

	if C.crypto_kdf_hkdf_sha256_extract_final(
		(*C.crypto_kdf_hkdf_sha256_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&masterKey[0])),
	) != 0 {
		return nil, errors.New("hkdf extract final failed")
	}

	if clearState {
		sodiumsecurememory.MemZero(state)
	}

	return masterKey, nil
}

func StateInitializationPtr(salt []byte) unsafe.Pointer {
	var state unsafe.Pointer
	isZero := true
	state, isZero = sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())
	if isZero == true {
		return nil
	}

	if salt == nil {
		C.crypto_kdf_hkdf_sha256_extract_init(
			(*C.crypto_kdf_hkdf_sha256_state)(state),
			nil,
			0,
		)
	} else {
		C.crypto_kdf_hkdf_sha256_extract_init(
			(*C.crypto_kdf_hkdf_sha256_state)(state),
			(*C.uchar)(unsafe.Pointer(&salt[0])),
			C.size_t(len(salt)),
		)
	}

	return state
}

func StateUpdatePtr(state unsafe.Pointer, ikm unsafe.Pointer, ikmLen int, clearKey bool) unsafe.Pointer {
	if state == nil || ikm == nil {
		return nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
	sodiumguardedheapallocation.SodiumMProtectReadOnly(ikm)

	C.crypto_kdf_hkdf_sha256_extract_update(
		(*C.crypto_kdf_hkdf_sha256_state)(state),
		(*C.uchar)(ikm),
		C.size_t(ikmLen),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(ikm)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(ikm)
		sodiumguardedheapallocation.SodiumFree(ikm)
	}

	return state
}

func ExtractMasterKeyFromFinalStatePtr(state unsafe.Pointer, clearState bool) unsafe.Pointer {
	if state == nil {
		return nil
	}

	var masterKey unsafe.Pointer
	isZero := true
	masterKey, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytesLength())
	if isZero == true {
		return nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)

	C.crypto_kdf_hkdf_sha256_extract_final(
		(*C.crypto_kdf_hkdf_sha256_state)(state),
		(*C.uchar)(masterKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(masterKey)

	if clearState {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
	}

	return masterKey
}
