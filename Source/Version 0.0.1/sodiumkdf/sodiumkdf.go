package sodiumkdf

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetKeyBytes() int {
	return int(C.crypto_kdf_keybytes())
}

func GetSubKeyMinimumApprovedLength() int {
	return int(C.crypto_kdf_bytes_min())
}

func GetSubKeyMaximumApprovedLength() int {
	return int(C.crypto_kdf_bytes_max())
}

func GetContextBytes() int {
	return int(C.crypto_kdf_contextbytes())
}

func GenerateKey() []byte {
	key := make([]byte, GetKeyBytes())
	C.crypto_kdf_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func GenerateKeyPtr() unsafe.Pointer {
	var isZero bool
	var key unsafe.Pointer
	key, isZero = sodiumguardedheapallocation.SodiumMalloc(GetKeyBytes())
	if isZero == true {
		return nil
	}

	C.crypto_kdf_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	return key
}

func KDFFunction(
	subKeyLength uint32,
	subKeyID uint64,
	context string,
	masterKey []byte,
	clearKey bool,
) ([]byte, error) {
	return KDFFunctionBytes(
		subKeyLength,
		subKeyID,
		[]byte(context),
		masterKey,
		clearKey,
	)
}

func KDFFunctionBytes(
	subKeyLength uint32,
	subKeyID uint64,
	context []byte,
	masterKey []byte,
	clearKey bool,
) ([]byte, error) {

	if context == nil {
		return nil, errors.New("context cannot be nil")
	}

	if int(subKeyLength) < GetSubKeyMinimumApprovedLength() ||
		int(subKeyLength) > GetSubKeyMaximumApprovedLength() {
		return nil, errors.New("invalid subkey length")
	}

	if len(context) > GetContextBytes() {
		return nil, errors.New("context too long")
	}

	if masterKey == nil {
		return nil, errors.New("master key cannot be nil")
	}

	subKey := make([]byte, subKeyLength)

	ret := C.crypto_kdf_derive_from_key(
		(*C.uchar)(unsafe.Pointer(&subKey[0])),
		C.size_t(subKeyLength),
		C.ulonglong(subKeyID),
		(*C.char)(unsafe.Pointer(&context[0])),
		(*C.uchar)(unsafe.Pointer(&masterKey[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(masterKey)
	}

	if ret != 0 {
		return nil, errors.New("failed to derive subkey")
	}

	return subKey, nil
}

func KDFFunctionPtr(
	subKeyLength int,
	subKeyID uint64,
	context string,
	masterKey unsafe.Pointer,
	clearKey bool,
) unsafe.Pointer {
	return KDFFunctionPtrBytes(
		subKeyLength,
		subKeyID,
		[]byte(context),
		masterKey,
		clearKey,
	)
}

func KDFFunctionPtrBytes(
	subKeyLength int,
	subKeyID uint64,
	context []byte,
	masterKey unsafe.Pointer,
	clearKey bool,
) unsafe.Pointer {

	if context == nil || masterKey == nil {
		return nil
	}

	if int(subKeyLength) < GetSubKeyMinimumApprovedLength() ||
		int(subKeyLength) > GetSubKeyMaximumApprovedLength() {
		return nil
	}

	if len(context) > GetContextBytes() {
		return nil
	}

	var subKey unsafe.Pointer
	var isZero bool
	subKey, isZero = sodiumguardedheapallocation.SodiumMalloc(subKeyLength)
	if isZero == true {
		return nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(masterKey)

	ret := C.crypto_kdf_derive_from_key(
		(*C.uchar)(subKey),
		C.size_t(subKeyLength),
		C.ulonglong(subKeyID),
		(*C.char)(unsafe.Pointer(&context[0])),
		(*C.uchar)(masterKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(masterKey)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(subKey)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(masterKey)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(masterKey)
	}

	if ret != 0 {
		sodiumguardedheapallocation.SodiumFree(subKey)
		return nil
	}

	return subKey
}
