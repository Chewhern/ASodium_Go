package sodiumscalarmult

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func CryptoScalarMultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}

func CryptoScalarMultScalarBytes() int {
	return int(C.crypto_scalarmult_scalarbytes())
}

func ScalarMultBase(
	secretKey []byte,
	clearKey bool,
) ([]byte, error) {

	if secretKey == nil || len(secretKey) != CryptoScalarMultScalarBytes() {
		return nil, errors.New("Error: Secret Key must be " +
			string(rune(CryptoScalarMultScalarBytes())) + " bytes")
	}

	publicKey := make([]byte, CryptoScalarMultBytes())

	C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return publicKey, nil
}

func ScalarMultBasePtr(
	secretKey unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if secretKey == nil {
		return nil, errors.New("Error: Secret Key must not be null or empty")
	}

	publicKey := make([]byte, CryptoScalarMultBytes())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)

	C.crypto_scalarmult_base(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(secretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return publicKey, nil
}

func ScalarMult(
	secretKey []byte,
	publicKey []byte,
	clearKey bool,
) ([]byte, error) {

	if secretKey == nil || len(secretKey) != CryptoScalarMultScalarBytes() {
		return nil, errors.New("Error: Secret Key must be " +
			string(rune(CryptoScalarMultScalarBytes())) + " bytes")
	}

	if publicKey == nil || len(publicKey) != CryptoScalarMultBytes() {
		return nil, errors.New("Error: Public Key must be " +
			string(rune(CryptoScalarMultBytes())) + " bytes")
	}

	sharedSecret := make([]byte, CryptoScalarMultBytes())

	C.crypto_scalarmult(
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return sharedSecret, nil
}

func ScalarMultPtr(
	secretKey unsafe.Pointer,
	publicKey []byte,
	clearKey bool,
) (unsafe.Pointer, error) {

	if secretKey == nil {
		return nil, errors.New("Error: Secret Key must not be null")
	}

	if publicKey == nil || len(publicKey) != CryptoScalarMultBytes() {
		return nil, errors.New("Error: Public Key must be " +
			string(rune(CryptoScalarMultBytes())) + " bytes")
	}

	sharedSecret, isZero := sodiumguardedheapallocation.SodiumMalloc(CryptoScalarMultBytes())
	if isZero {
		return nil, errors.New("Failed to allocate shared secret")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)

	C.crypto_scalarmult(
		(*C.uchar)(sharedSecret),
		(*C.uchar)(secretKey),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return sharedSecret, nil
}
