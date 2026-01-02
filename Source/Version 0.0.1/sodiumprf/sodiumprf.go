package sodiumprf

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"ASodium/sodiumstreamciphersalsa20"
	"errors"
	"unsafe"
)

func NonceExtension(nonce []byte, key []byte, constant []byte, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != 16 {
		return nil, errors.New("Error: Nonce must be 16 bytes in length")
	}
	if key == nil || len(key) != 32 {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if constant != nil && len(constant) != 16 {
		return nil, errors.New("Error: Constant must be 16 bytes in length")
	}

	extendedNonce := make([]byte, 32)
	C.crypto_core_hchacha20(
		(*C.uchar)(unsafe.Pointer(&extendedNonce[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		func() *C.uchar {
			if constant == nil {
				return nil
			}
			return (*C.uchar)(unsafe.Pointer(&constant[0]))
		}(),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return extendedNonce, nil
}

// NonceExtension using IntPtr-style (libsodium guarded memory)
func NonceExtensionPtr(nonce []byte, keyPtr unsafe.Pointer, constant []byte, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != 16 {
		return nil, errors.New("Error: Nonce must be 16 bytes in length")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if constant != nil && len(constant) != 16 {
		return nil, errors.New("Error: Constant must be 16 bytes in length")
	}

	extendedNonce := make([]byte, 32)

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	C.crypto_core_hchacha20(
		(*C.uchar)(unsafe.Pointer(&extendedNonce[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
		func() *C.uchar {
			if constant == nil {
				return nil
			}
			return (*C.uchar)(unsafe.Pointer(&constant[0]))
		}(),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return extendedNonce, nil
}

// Salsa20PRF using byte slice key
func Salsa20PRF(randomOutputLength int64, nonce []byte, key []byte, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != 32 {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)
	C.crypto_stream_salsa20(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return randomOutput, nil
}

// Salsa20PRF using IntPtr-style key
func Salsa20PRFPtr(randomOutputLength int64, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)
	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	C.crypto_stream_salsa20(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return randomOutput, nil
}

// Salsa2012PRF using byte slice key
func Salsa2012PRF(randomOutputLength int64, nonce []byte, key []byte, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != 32 {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)
	C.crypto_stream_salsa2012(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return randomOutput, nil
}

// Salsa2012PRF using IntPtr-style key
func Salsa2012PRFPtr(randomOutputLength int64, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	C.crypto_stream_salsa2012(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return randomOutput, nil
}

// Salsa208PRF using byte slice key
func Salsa208PRF(randomOutputLength int64, nonce []byte, key []byte, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != 32 {
		return nil, errors.New("Error: Key must be 32 bytes in length")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)
	C.crypto_stream_salsa208(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return randomOutput, nil
}

// Salsa208PRF using IntPtr-style key
func Salsa208PRFPtr(randomOutputLength int64, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if nonce == nil || len(nonce) != sodiumstreamciphersalsa20.GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if randomOutputLength < 0 {
		return nil, errors.New("Error: Random output length must not be negative")
	}

	randomOutput := make([]byte, randomOutputLength)

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	C.crypto_stream_salsa208(
		(*C.uchar)(unsafe.Pointer(&randomOutput[0])),
		C.ulonglong(randomOutputLength),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return randomOutput, nil
}
