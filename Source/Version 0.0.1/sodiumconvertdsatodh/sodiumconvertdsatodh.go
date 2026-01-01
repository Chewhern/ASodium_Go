package sodiumconvertdsatodh

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumpublickeyauth"
	"ASodium/sodiumpublickeybox"
	"ASodium/sodiumsecurememory"
	"fmt"
	"unsafe"
)

func ConvertDSAPKToDHPK(ed25519PK []byte) ([]byte, error) {
	if ed25519PK == nil {
		return nil, fmt.Errorf("ED25519PK must not be nil")
	}

	if len(ed25519PK) != sodiumpublickeyauth.GetPublicKeyBytesLength() {
		return nil, fmt.Errorf(
			"ED25519 public key length must be %d bytes",
			sodiumpublickeyauth.GetPublicKeyBytesLength(),
		)
	}

	x25519PK := make([]byte, sodiumpublickeyauth.GetPublicKeyBytesLength())

	rc := C.crypto_sign_ed25519_pk_to_curve25519(
		(*C.uchar)(&x25519PK[0]),
		(*C.uchar)(&ed25519PK[0]),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to convert ED25519 PK to X25519 PK")
	}

	return x25519PK, nil
}

func ConvertDSASKToDHSK(ed25519SK []byte, clearKey bool) ([]byte, error) {
	if ed25519SK == nil {
		return nil, fmt.Errorf("ED25519SK must not be nil")
	}

	if len(ed25519SK) != sodiumpublickeyauth.GetSecretKeyBytesLength() {
		return nil, fmt.Errorf(
			"ED25519 secret key length must be %d bytes",
			sodiumpublickeyauth.GetSecretKeyBytesLength(),
		)
	}

	x25519SK := make([]byte, sodiumpublickeybox.GetSecretKeyBytesLength())

	rc := C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(&x25519SK[0]),
		(*C.uchar)(&ed25519SK[0]),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to convert ED25519 SK to X25519 SK")
	}

	if clearKey {
		sodiumsecurememory.MemZero(ed25519SK)
	}

	return x25519SK, nil
}

func ConvertDSASKToDHSKPtr(
	ed25519SK unsafe.Pointer,
	clearKey bool,
) (unsafe.Pointer, error) {

	if ed25519SK == nil {
		return nil, fmt.Errorf("ED25519SK pointer must not be nil")
	}

	const tryAttempts = 5
	keyLen := int(sodiumpublickeybox.GetSecretKeyBytesLength())

	var (
		x25519SK unsafe.Pointer
		isZero   = true
	)

	for i := 0; i < tryAttempts && isZero; i++ {
		x25519SK, isZero = sodiumguardedheapallocation.SodiumMalloc(keyLen)
		if x25519SK != nil {
			isZero = false
		}
	}

	if isZero {
		return nil, fmt.Errorf("failed to allocate guarded memory for X25519 SK")
	}

	// Protect input key
	sodiumguardedheapallocation.SodiumMProtectReadOnly(ed25519SK)

	rc := C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(x25519SK),
		(*C.uchar)(ed25519SK),
	)

	if rc != 0 {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(x25519SK)
		sodiumguardedheapallocation.SodiumFree(x25519SK)
		return nil, fmt.Errorf("failed to convert ED25519 SK to X25519 SK")
	}

	// Lock both keys
	sodiumguardedheapallocation.SodiumMProtectNoAccess(ed25519SK)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(x25519SK)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(ed25519SK)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(ed25519SK)
	}

	return x25519SK, nil
}
