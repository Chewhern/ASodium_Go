package sodiumsecretaeadaes256gcmpc

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/detachedbox"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecretaeadaes256gcm"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetStateBytesLength() int {
	return int(C.crypto_aead_aes256gcm_statebytes())
}

func InitializeState(key []byte, clearKey bool) ([]byte, error) {
	if key == nil || len(key) != sodiumsecretaeadaes256gcm.AES256GCMKeyBytes() {
		return nil, errors.New("key must be 32 bytes")
	}

	state := make([]byte, GetStateBytesLength())

	ret := C.crypto_aead_aes256gcm_beforenm(
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("failed to initialize AES256-GCM state")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return state, nil
}

func InitializeStatePtr(key unsafe.Pointer, clearKey bool) (unsafe.Pointer, error) {
	if key == nil {
		return nil, errors.New("key must not be null")
	}

	state, isZero := sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())
	if state == nil || isZero == true {
		return nil, nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	ret := C.crypto_aead_aes256gcm_beforenm((*C.crypto_aead_aes256gcm_state)(state), (*C.uchar)(key))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("failed to initialize AES256-GCM state")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return state, nil
}

func Encrypt(
	message []byte,
	noncePublic []byte,
	state []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if state == nil || len(state) != GetStateBytesLength() {
		return nil, errors.New("state bytes length invalid")
	}
	if noncePublic == nil || len(noncePublic) != sodiumsecretaeadaes256gcm.AES256GCMNpubBytes() {
		return nil, errors.New("invalid public nonce length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != sodiumsecretaeadaes256gcm.AES256GCMNsecBytes() {
		return nil, errors.New("invalid security nonce length")
	}

	cipher := make([]byte, len(message)+sodiumsecretaeadaes256gcm.AES256GCMNsecBytes())

	var adPtr unsafe.Pointer
	if additionalData != nil {
		adPtr = unsafe.Pointer(&additionalData[0])
	}

	ret := C.crypto_aead_aes256gcm_encrypt_afternm(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(adPtr),
		C.ulonglong(len(additionalData)),
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&state[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(state)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("encryption failed")
	}

	return cipher, nil
}

func EncryptPtr(
	message []byte,
	noncePublic []byte,
	state unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if state == nil {
		return nil, errors.New("state must not be null")
	}

	cipher := make([]byte, len(message)+sodiumsecretaeadaes256gcm.AES256GCMABytes())

	var adPtr unsafe.Pointer
	if additionalData != nil {
		adPtr = unsafe.Pointer(&additionalData[0])
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_encrypt_afternm(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(adPtr),
		C.ulonglong(len(additionalData)),
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(state),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("encryption failed")
	}

	return cipher, nil
}

func Decrypt(
	cipher []byte,
	noncePublic []byte,
	state []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	msg := make([]byte, len(cipher)-sodiumsecretaeadaes256gcm.AES256GCMABytes())

	var adPtr unsafe.Pointer
	if additionalData != nil {
		adPtr = unsafe.Pointer(&additionalData[0])
	}

	ret := C.crypto_aead_aes256gcm_decrypt_afternm(
		(*C.uchar)(unsafe.Pointer(&msg[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		C.ulonglong(len(cipher)),
		(*C.uchar)(adPtr),
		C.ulonglong(len(additionalData)),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&state[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(state)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("MAC verification failed")
	}

	return msg, nil
}

func DecryptPtr(
	cipher []byte,
	noncePublic []byte,
	state unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if state == nil {
		return nil, errors.New("Error: StateBytes must not be null")
	}

	msg := make([]byte, len(cipher)-sodiumsecretaeadaes256gcm.AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil && len(additionalData) != 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_decrypt_afternm(
		(*C.uchar)(unsafe.Pointer(&msg[0])),
		nil,
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		C.ulonglong(len(cipher)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(state),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("Error: Verification of MAC failed")
	}

	return msg, nil
}

func CreateDetachedBox(
	message []byte,
	noncePublic []byte,
	state []byte,
	nonceSecurity []byte,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	cipher := make([]byte, len(message))
	mac := make([]byte, sodiumsecretaeadaes256gcm.AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil && len(additionalData) != 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_encrypt_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&state[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(state)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("Error: Failed to create detached box")
	}

	return detachedbox.NewDetachedBox(cipher, mac), nil
}

func CreateDetachedBoxPtr(
	message []byte,
	noncePublic []byte,
	state unsafe.Pointer,
	nonceSecurity unsafe.Pointer,
	additionalData []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	cipher := make([]byte, len(message))
	mac := make([]byte, sodiumsecretaeadaes256gcm.AES256GCMABytes())

	var adLen C.ulonglong
	if additionalData != nil && len(additionalData) != 0 {
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_encrypt_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		nil,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		adLen,
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(state),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret != 0 {
		return nil, errors.New("Error: Failed to create detached box")
	}

	return detachedbox.NewDetachedBox(cipher, mac), nil
}

func OpenDetachedBoxFromStructStateBytes(
	box *detachedbox.DetachedBox,
	noncePublic []byte,
	stateBytes []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {
	return OpenDetachedBoxStateBytes(
		box.CipherText,
		box.Mac,
		noncePublic,
		stateBytes,
		additionalData,
		nonceSecurity,
		clearKey,
	)
}

func OpenDetachedBoxStateBytes(
	cipherText []byte,
	mac []byte,
	noncePublic []byte,
	stateBytes []byte,
	additionalData []byte,
	nonceSecurity []byte,
	clearKey bool,
) ([]byte, error) {

	if stateBytes == nil || len(stateBytes) != GetStateBytesLength() {
		return nil, errors.New("Error: StateBytes must be correct length")
	}
	if noncePublic == nil || len(noncePublic) != sodiumsecretaeadaes256gcm.AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce incorrect length")
	}
	if nonceSecurity != nil && len(nonceSecurity) != sodiumsecretaeadaes256gcm.AES256GCMNsecBytes() {
		return nil, errors.New("Error: Nonce Security length invalid")
	}

	message := make([]byte, len(cipherText))

	var adPtr *C.uchar
	var adLen C.ulonglong
	if additionalData != nil && len(additionalData) > 0 {
		adPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
		adLen = C.ulonglong(len(additionalData))
	}

	ret := C.crypto_aead_aes256gcm_decrypt_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&nonceSecurity[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		adPtr,
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&stateBytes[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(stateBytes)
		sodiumsecurememory.MemZero(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("Error: Failed to open detached box")
	}

	return message, nil
}

func OpenDetachedBoxFromStructPtr(
	box *detachedbox.DetachedBox,
	noncePublic []byte,
	statePtr unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return OpenDetachedBoxPtr(
		box.CipherText,
		box.Mac,
		noncePublic,
		statePtr,
		additionalData,
		nonceSecurity,
		clearKey,
	)
}

func OpenDetachedBoxPtr(
	cipherText []byte,
	mac []byte,
	noncePublic []byte,
	statePtr unsafe.Pointer,
	additionalData []byte,
	nonceSecurity unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if statePtr == nil {
		return nil, errors.New("Error: StateBytes must not be null")
	}
	if noncePublic == nil || len(noncePublic) != sodiumsecretaeadaes256gcm.AES256GCMNpubBytes() {
		return nil, errors.New("Error: Public nonce incorrect length")
	}
	if nonceSecurity != nil {
		return nil, errors.New("Error: Nonce Security must not be empty")
	}

	message := make([]byte, len(cipherText))

	var adPtr *C.uchar
	var adLen C.ulonglong
	if additionalData != nil && len(additionalData) > 0 {
		adPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
		adLen = C.ulonglong(len(additionalData))
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(statePtr)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(nonceSecurity)
	}

	ret := C.crypto_aead_aes256gcm_decrypt_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(nonceSecurity),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		adPtr,
		adLen,
		(*C.uchar)(unsafe.Pointer(&noncePublic[0])),
		(*C.crypto_aead_aes256gcm_state)(statePtr),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(statePtr)

	if nonceSecurity != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(nonceSecurity)
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(statePtr)
		sodiumguardedheapallocation.SodiumFree(statePtr)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(nonceSecurity)
		sodiumguardedheapallocation.SodiumFree(nonceSecurity)
	}

	if ret == -1 {
		return nil, errors.New("Error: Failed to open detached box")
	}

	return message, nil
}
