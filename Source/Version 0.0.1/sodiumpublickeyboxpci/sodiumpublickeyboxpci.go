package sodiumpublickeyboxpci

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/detachedbox"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumpublickeybox"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetBeforeNMBytesLength() int {
	return int(C.crypto_box_beforenmbytes())
}

func CalculateSharedSecret(
	otherUserPublicKey []byte,
	currentUserPrivateKey []byte,
	clearKey bool,
) ([]byte, error) {

	if otherUserPublicKey == nil {
		return nil, errors.New("Error: Other User Public Key can't be null")
	}
	if len(otherUserPublicKey) != sodiumpublickeybox.GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Other User Public Key must be correct length")
	}

	if currentUserPrivateKey == nil {
		return nil, errors.New("Error: Current User Private Key can't be null")
	}
	if len(currentUserPrivateKey) != sodiumpublickeybox.GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Current User Private Key must be correct length")
	}

	sharedSecret := make([]byte, GetBeforeNMBytesLength())

	ret := C.crypto_box_beforenm(
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(unsafe.Pointer(&currentUserPrivateKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to calculate shared secret")
	}

	if clearKey {
		sodiumsecurememory.MemZero(currentUserPrivateKey)
	}

	return sharedSecret, nil
}

func CalculateSharedSecretPtr(
	otherUserPublicKey []byte,
	currentUserPrivateKey unsafe.Pointer,
	clearKey bool,
) (unsafe.Pointer, error) {

	if otherUserPublicKey == nil {
		return nil, errors.New("Error: Other User Public Key can't be null")
	}
	if len(otherUserPublicKey) != sodiumpublickeybox.GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Other User Public Key must be correct length")
	}

	if currentUserPrivateKey == nil {
		return nil, errors.New("Error: Current User Private Key can't be null")
	}

	sharedSecret, isZero := sodiumguardedheapallocation.SodiumMalloc(GetBeforeNMBytesLength())
	if isZero {
		return nil, nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentUserPrivateKey)

	ret := C.crypto_box_beforenm(
		(*C.uchar)(sharedSecret),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(currentUserPrivateKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentUserPrivateKey)

	if ret != 0 {
		return nil, errors.New("Failed to calculate shared secret")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentUserPrivateKey)
		sodiumguardedheapallocation.SodiumFree(currentUserPrivateKey)
	}

	return sharedSecret, nil
}

func GenerateNonce() []byte {
	return sodiumrng.GetRandomBytes(sodiumpublickeybox.GetNonceBytesLength())
}

func CreateAfterNM(
	message []byte,
	nonce []byte,
	sharedSecret []byte,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil || len(sharedSecret) != GetBeforeNMBytesLength() {
		return nil, errors.New("Error: Shared Secret must be correct length")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}

	cipherText := make([]byte, len(message)+sodiumpublickeybox.GetMACBytesLength())

	ret := C.crypto_box_easy_afternm(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(sharedSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create PublicKeyBox")
	}

	return cipherText, nil
}

func CreateAfterNMPtr(
	message []byte,
	nonce []byte,
	sharedSecret unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil {
		return nil, errors.New("Error: Shared Secret must not be null")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}

	cipherText := make([]byte, len(message)+sodiumpublickeybox.GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(sharedSecret)

	ret := C.crypto_box_easy_afternm(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(sharedSecret),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(sharedSecret)
		sodiumguardedheapallocation.SodiumFree(sharedSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create PublicKeyBox")
	}

	return cipherText, nil
}

func OpenAfterNM(
	cipherText []byte,
	nonce []byte,
	sharedSecret []byte,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil || len(sharedSecret) != GetBeforeNMBytesLength() {
		return nil, errors.New("Error: Shared Secret must be correct length")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}

	// Trim legacy MAC_BYTES zero prefix
	if cipherText[0] == 0 {
		trim := true
		for i := 0; i < sodiumpublickeybox.GetMACBytesLength()-1; i++ {
			if cipherText[i] != 0 {
				trim = false
				break
			}
		}
		if trim {
			cipherText = cipherText[sodiumpublickeybox.GetMACBytesLength():]
		}
	}

	message := make([]byte, len(cipherText)-sodiumpublickeybox.GetMACBytesLength())

	ret := C.crypto_box_open_easy_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to open PublicKeyBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(sharedSecret)
	}

	return message, nil
}

func OpenAfterNMPtr(
	cipherText []byte,
	nonce []byte,
	sharedSecret unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil {
		return nil, errors.New("Error: Shared Secret must not be null/empty")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be exact length")
	}

	// legacy trim logic (MAC_BYTES leading zeros)
	if len(cipherText) > 0 && cipherText[0] == 0 {
		trim := true
		for i := 0; i < sodiumpublickeybox.GetMACBytesLength()-1; i++ {
			if cipherText[i] != 0 {
				trim = false
				break
			}
		}
		if trim {
			cipherText = cipherText[sodiumpublickeybox.GetMACBytesLength():]
		}
	}

	message := make([]byte, len(cipherText)-sodiumpublickeybox.GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(sharedSecret)
	ret := C.crypto_box_open_easy_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(sharedSecret),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if ret != 0 {
		return nil, errors.New("Failed to open PublicKeyBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(sharedSecret)
		sodiumguardedheapallocation.SodiumFree(sharedSecret)
	}

	return message, nil
}

func BoxCreateDetachedAfterNM(
	message []byte,
	nonce []byte,
	sharedSecret []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if sharedSecret == nil || len(sharedSecret) != GetBeforeNMBytesLength() {
		return nil, errors.New("Error: Shared Secret must be correct length")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, sodiumpublickeybox.GetMACBytesLength())

	ret := C.crypto_box_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(sharedSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create public detached Box")
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func BoxCreateDetachedAfterNMPtr(
	message []byte,
	nonce []byte,
	sharedSecret unsafe.Pointer,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if sharedSecret == nil {
		return nil, errors.New("Error: Shared Secret must not be null/empty")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, sodiumpublickeybox.GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(sharedSecret)
	ret := C.crypto_box_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(sharedSecret),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(sharedSecret)
		sodiumguardedheapallocation.SodiumFree(sharedSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create public detached Box")
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func BoxOpenDetachedAfterNM(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	sharedSecret []byte,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil || len(sharedSecret) != GetBeforeNMBytesLength() {
		return nil, errors.New("Error: Shared Secret must be correct length")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}
	if mac == nil || len(mac) != sodiumpublickeybox.GetMACBytesLength() {
		return nil, errors.New("Error: MAC must be correct length")
	}

	message := make([]byte, len(cipherText))

	ret := C.crypto_box_open_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to open public detached Box")
	}

	if clearKey {
		sodiumsecurememory.MemZero(sharedSecret)
	}

	return message, nil
}

func BoxOpenDetachedAfterNMPtr(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	sharedSecret unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if sharedSecret == nil {
		return nil, errors.New("Error: Shared Secret must not be null/empty")
	}
	if nonce == nil || len(nonce) != sodiumpublickeybox.GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce must be correct length")
	}
	if mac == nil || len(mac) != sodiumpublickeybox.GetMACBytesLength() {
		return nil, errors.New("Error: MAC must be correct length")
	}

	message := make([]byte, len(cipherText))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(sharedSecret)
	ret := C.crypto_box_open_detached_afternm(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(sharedSecret),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(sharedSecret)

	if ret != 0 {
		return nil, errors.New("Failed to open public detached Box")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(sharedSecret)
		sodiumguardedheapallocation.SodiumFree(sharedSecret)
	}

	return message, nil
}
