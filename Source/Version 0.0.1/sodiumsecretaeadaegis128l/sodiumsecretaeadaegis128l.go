package sodiumsecretaeadaegis128l

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

func AEGIS128LKeyBytes() int {
	return int(C.crypto_aead_aegis128l_keybytes())
}

func AEGIS128LNpubBytes() int {
	return int(C.crypto_aead_aegis128l_npubbytes())
}

func AEGIS128LNsecBytes() int {
	return int(C.crypto_aead_aegis128l_nsecbytes())
}

func AEGIS128LABytes() int {
	return int(C.crypto_aead_aegis128l_abytes())
}

func AEGIS128LMessageBytesMax() uint64 {
	return uint64(C.crypto_aead_aegis128l_messagebytes_max())
}

func AEGIS128LGeneratePublicNonce() []byte {
	return sodiumrng.GetRandomBytes(AEGIS128LNpubBytes())
}

func AEGIS128LGenerateSecurityNonce() []byte {
	return sodiumrng.GetRandomBytes(AEGIS128LNsecBytes())
}

func AEGIS128LGenerateKey() []byte {
	key := make([]byte, AEGIS128LKeyBytes())
	C.crypto_aead_aegis128l_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func AEGIS128LGenerateKeyPtr() unsafe.Pointer {
	key, localZero := sodiumguardedheapallocation.SodiumMalloc(AEGIS128LKeyBytes())

	if localZero {
		return nil
	}

	C.crypto_aead_aegis128l_keygen((*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)
	return key
}

func AEGIS128LEncrypt(
	message []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AEGIS128LKeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS128LNsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	cipher := make([]byte, len(message)+AEGIS128LABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis128l_encrypt(
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
		return nil, errors.New("AEGIS128L encryption failed")
	}

	return cipher, nil
}

func AEGIS128LEncryptPtr(
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
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}

	cipher := make([]byte, len(message)+AEGIS128LABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis128l_encrypt(
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
		return nil, errors.New("AEGIS128L encryption failed")
	}

	return cipher, nil
}

func AEGIS128LDecrypt(
	cipher []byte,
	noncePublic []byte,
	key []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if key == nil || len(key) != AEGIS128LKeyBytes() {
		return nil, errors.New("key length invalid")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("public nonce length invalid")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS128LNsecBytes() {
		return nil, errors.New("security nonce length invalid")
	}

	message := make([]byte, len(cipher)-AEGIS128LABytes())
	var adLen C.ulonglong

	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis128l_decrypt(
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
		return nil, errors.New("AEGIS128L authentication failed")
	}

	return message, nil
}

func ptrOrNil(b []byte) *C.uchar {
	if b == nil || len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func AEGIS128LDecryptPtr(
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
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	message := make([]byte, len(cipherText)-AEGIS128LABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis128l_decrypt(
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

func AEGIS128LCreateDetached(
	message []byte,
	noncePublic []byte,
	key []byte,
	nonceSecurity []byte,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if key == nil || len(key) != AEGIS128LKeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS128LNsecBytes() {
		return nil, errors.New("Error: Nonce Security must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AEGIS128LABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis128l_encrypt_detached(
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

func AEGIS128LCreateDetachedPtr(
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
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("Error: Public nonce must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, AEGIS128LABytes())

	var adLen C.ulonglong
	if additionalData != nil {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aegis128l_encrypt_detached(
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

	if key == nil || len(key) != AEGIS128LKeyBytes() {
		return nil, errors.New("Error: Key must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AEGIS128LABytes() {
		return nil, errors.New("Error: MAC invalid length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != AEGIS128LNsecBytes() {
		return nil, errors.New("Error: Security nonce invalid length")
	}

	message := make([]byte, len(cipherText))
	var adLen C.ulonglong

	if additionalData != nil && len(additionalData) > 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aegis128l_decrypt_detached(
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
	if noncePublic == nil || len(noncePublic) != AEGIS128LNpubBytes() {
		return nil, errors.New("Error: Public nonce invalid length")
	}
	if mac == nil || len(mac) != AEGIS128LABytes() {
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

	ret := C.crypto_aead_aegis128l_decrypt_detached(
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
