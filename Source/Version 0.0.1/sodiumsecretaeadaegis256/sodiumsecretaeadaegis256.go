package sodiumsecretaeadaegis256

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/detachedbox"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func AEGIS256KeyBytes() int {
	return int(C.crypto_aead_aegis256_keybytes())
}

func AEGIS256NpubBytes() int {
	return int(C.crypto_aead_aegis256_npubbytes())
}

func AEGIS256NsecBytes() int {
	return int(C.crypto_aead_aegis256_nsecbytes())
}

func AEGIS256ABytes() int {
	return int(C.crypto_aead_aegis256_abytes())
}

func AEGIS256MessageBytesMax() uint64 {
	return uint64(C.crypto_aead_aegis256_messagebytes_max())
}

func AEGIS256GeneratePublicNonce() []byte {
	return sodiumrng.GetRandomBytes(AEGIS256NpubBytes())
}

func AEGIS256GenerateSecurityNonce() []byte {
	return sodiumrng.GetRandomBytes(AEGIS256NsecBytes())
}

func AEGIS256GenerateKey() []byte {
	key := make([]byte, AEGIS256KeyBytes())
	C.crypto_aead_aegis256_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func AEGIS256GenerateKeyPtr() unsafe.Pointer {
	key, localZero := sodiumguardedheapallocation.SodiumMalloc(AEGIS256KeyBytes())

	if localZero {
		return nil
	}

	C.crypto_aead_aegis256_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
	return key
}

func AEGIS256Encrypt(
	message []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AEGIS256KeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS256NsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	cipher := make([]byte, len(message)+AEGIS256ABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis256_encrypt(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		ptrOrNil(additionalData),
		adLen,
		ptrOrNil(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("AEGIS256 encryption failed")
	}

	return cipher, nil
}

func AEGIS256EncryptPtr(
	message []byte,
	noncePublic []byte,
	key unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if key == nil {
		return nil, errors.New("key is null")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}

	cipher := make([]byte, len(message)+AEGIS256ABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis256_encrypt(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		ptrOrNil(additionalData),
		adLen,
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("AEGIS256 encryption failed")
	}

	return cipher, nil
}

func AEGIS256Decrypt(
	cipher []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AEGIS256KeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS256NsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	message := make([]byte, len(cipher)-AEGIS256ABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis256_decrypt(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		nil,
		ptrOrNil(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		C.ulonglong(len(cipher)),
		ptrOrNil(additionalData),
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("AEGIS256 authentication failed")
	}

	return message, nil
}

func ptrOrNil(b []byte) *C.uchar {
	if b == nil || len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func AEGIS256DecryptPtr(
	cipherText []byte,
	noncePublic []byte,
	key unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if key == nil {
		return nil, errors.New("Error: Key must not be null/empty")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	message := make([]byte, len(cipherText)-AEGIS256ABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis256_decrypt(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		nil,
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("Error: Verification of MAC stored in cipher text failed")
	}

	return message, nil
}

func AEGIS256CreateDetached(
	message []byte,
	noncePublic []byte,
	key []byte,
	nonceSecurity []byte,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if key == nil || len(key) != AEGIS256KeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS256NsecBytes() {
		return nil, errors.New("Error: Nonce Security must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AEGIS256ABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis256_encrypt_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("Error: Failed to create detached box")
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func AEGIS256CreateDetachedPtr(
	message []byte,
	noncePublic []byte,
	key unsafe.Pointer,
	nonceSecurity unsafe.Pointer,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if key == nil {
		return nil, errors.New("Error: Key must not be empty/null")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AEGIS256ABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis256_encrypt_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("Error: Failed to create detached box")
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func OpenDetachedBox(
	box *detachedbox.DetachedBox,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	return OpenDetachedBoxRaw(
		box.CipherText,
		box.Mac,
		noncePublic,
		key,
		additionalData,
		nonceSecurity,
		clearKey,
	)
}

func OpenDetachedBoxPtr(
	box *detachedbox.DetachedBox,
	noncePublic []byte,
	key unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	return OpenDetachedBoxRawPtr(
		box.CipherText,
		box.Mac,
		noncePublic,
		key,
		additionalData,
		nonceSecurity,
		clearKey,
	)
}

func OpenDetachedBoxRaw(
	cipherText []byte,
	mac []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AEGIS256KeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AEGIS256ABytes() {
		return nil, errors.New("Error: MAC invalid length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS256NsecBytes() {
		return nil, errors.New("Error: Security nonce invalid length")
	}

	message := make([]byte, len(cipherText))
	var adLen C.ulonglong

	if additionalData != nil && len(additionalData) > 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis256_decrypt_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(key)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("Error: Failed to open detached box")
	}

	return message, nil
}

func OpenDetachedBoxRawPtr(
	cipherText []byte,
	mac []byte,
	noncePublic []byte,
	key unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS256NpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AEGIS256ABytes() {
		return nil, errors.New("Error: MAC invalid length")
	}

	message := make([]byte, len(cipherText))
	var adLen C.ulonglong

	if additionalData != nil && len(additionalData) > 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis256_decrypt_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("Error: Failed to open detached box")
	}

	return message, nil
}
