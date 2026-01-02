package sodiumsecretaeadaes256gcm

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

func isAES256GCMAvailable() bool {
	var testint = int(C.crypto_aead_aes256gcm_is_available())
	if testint == 1 {
		return true
	} else {
		return false
	}
}

func AES256GCMKeyBytes() int {
	return int(C.crypto_aead_aes256gcm_keybytes())
}

func AES256GCMNpubBytes() int {
	return int(C.crypto_aead_aes256gcm_npubbytes())
}

func AES256GCMNsecBytes() int {
	return int(C.crypto_aead_aes256gcm_nsecbytes())
}

func AES256GCMABytes() int {
	return int(C.crypto_aead_aes256gcm_abytes())
}

func AES256GCMMessageBytesMax() uint64 {
	return uint64(C.crypto_aead_aes256gcm_messagebytes_max())
}

func AES256GCMGeneratePublicNonce() []byte {
	return sodiumrng.GetRandomBytes(AES256GCMNpubBytes())
}

func AES256GCMGenerateSecurityNonce() []byte {
	return sodiumrng.GetRandomBytes(AES256GCMNsecBytes())
}

func AES256GCMGenerateKey() []byte {
	key := make([]byte, AES256GCMKeyBytes())
	C.crypto_aead_aes256gcm_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func AES256GCMGenerateKeyPtr() unsafe.Pointer {
	key, localZero := sodiumguardedheapallocation.SodiumMalloc(AES256GCMKeyBytes())

	if localZero {
		return nil
	}

	C.crypto_aead_aes256gcm_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
	return key
}

func AES256GCMEncrypt(
	message []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AES256GCMKeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AES256GCMNsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	cipher := make([]byte, len(message)+AES256GCMABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_encrypt(
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
		return nil, errors.New("AES256GCM encryption failed")
	}

	return cipher, nil
}

func AES256GCMEncryptPtr(
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
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}

	cipher := make([]byte, len(message)+AES256GCMABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_encrypt(
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
		return nil, errors.New("AES256GCM encryption failed")
	}

	return cipher, nil
}

func AES256GCMDecrypt(
	cipher []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AES256GCMKeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AES256GCMNsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	message := make([]byte, len(cipher)-AES256GCMABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_decrypt(
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
		return nil, errors.New("AES256GCM authentication failed")
	}

	return message, nil
}

func ptrOrNil(b []byte) *C.uchar {
	if b == nil || len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func AES256GCMDecryptPtr(
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
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	message := make([]byte, len(cipherText)-AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_decrypt(
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

func AES256GCMCreateDetached(
	message []byte,
	noncePublic []byte,
	key []byte,
	nonceSecurity []byte,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if key == nil || len(key) != AES256GCMKeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AES256GCMNsecBytes() {
		return nil, errors.New("Error: Nonce Security must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_encrypt_detached(
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

func AES256GCMCreateDetachedPtr(
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
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_encrypt_detached(
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

	if key == nil || len(key) != AES256GCMKeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AES256GCMABytes() {
		return nil, errors.New("Error: MAC invalid length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AES256GCMNsecBytes() {
		return nil, errors.New("Error: Security nonce invalid length")
	}

	message := make([]byte, len(cipherText))
	var adLen C.ulonglong

	if additionalData != nil && len(additionalData) > 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_decrypt_detached(
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
	if noncePublic == nil || len(noncePublic) != AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AES256GCMABytes() {
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

	ret := C.crypto_aead_aes256gcm_decrypt_detached(
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
