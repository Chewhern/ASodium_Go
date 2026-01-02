package sodiumpublickeybox

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/detachedbox"
	"ASodium/keypair"
	"ASodium/revampedkeypair"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetSeedBytesLength() int {
	return int(C.crypto_box_seedbytes())
}

func GetPublicKeyBytesLength() int {
	return int(C.crypto_box_publickeybytes())
}

func GetSecretKeyBytesLength() int {
	return int(C.crypto_box_secretkeybytes())
}

func GetNonceBytesLength() int {
	return int(C.crypto_box_noncebytes())
}

func GetBoxZeroBytesLength() int {
	return int(C.crypto_box_boxzerobytes())
}

func GetMACBytesLength() int {
	return int(C.crypto_box_macbytes())
}

func GetMaxMessageBytesLength() int64 {
	return int64(C.crypto_box_messagebytes_max())
}

func GenerateKeyPair() *keypair.KeyPair {

	pub, isZero1 := sodiumguardedheapallocation.SodiumMalloc(GetPublicKeyBytesLength())
	sec, isZero2 := sodiumguardedheapallocation.SodiumMalloc(GetSecretKeyBytesLength())

	if !isZero1 && !isZero2 {
		C.crypto_box_keypair(
			(*C.uchar)(pub),
			(*C.uchar)(sec),
		)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(sec)

		return keypair.NewKeyPair(
			sec, GetSecretKeyBytesLength(),
			pub, GetPublicKeyBytesLength(),
		)
	}

	return keypair.NewKeyPair(nil, 0, nil, 0)
}

func GenerateRevampedKeyPair() (*revampedkeypair.RevampedKeyPair, error) {
	pub := make([]byte, GetPublicKeyBytesLength())
	sec := make([]byte, GetSecretKeyBytesLength())

	C.crypto_box_keypair(
		(*C.uchar)(unsafe.Pointer(&pub[0])),
		(*C.uchar)(unsafe.Pointer(&sec[0])),
	)

	mykeypair, myerror := revampedkeypair.NewRevampedKeyPair(pub, sec)

	return mykeypair, myerror
}

func GenerateSeededKeyPair(seed unsafe.Pointer, clearKey bool) (*keypair.KeyPair, error) {
	if seed == nil {
		return &keypair.KeyPair{}, errors.New("Error:Seed must not be null")
	}

	pub, isZero1 := sodiumguardedheapallocation.SodiumMalloc(GetPublicKeyBytesLength())
	sec, isZero2 := sodiumguardedheapallocation.SodiumMalloc(GetSecretKeyBytesLength())

	if !isZero1 && !isZero2 {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(seed)

		C.crypto_box_seed_keypair(
			(*C.uchar)(pub),
			(*C.uchar)(sec),
			(*C.uchar)(seed),
		)

		sodiumguardedheapallocation.SodiumMProtectNoAccess(seed)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(sec)

		if clearKey {
			sodiumguardedheapallocation.SodiumMProtectReadWrite(seed)
			sodiumguardedheapallocation.SodiumFree(seed)
		}

		return keypair.NewKeyPair(
			sec, GetSecretKeyBytesLength(),
			pub, GetPublicKeyBytesLength(),
		), nil
	}

	return keypair.NewKeyPairEmpty(), nil
}

func GenerateSeededRevampedKeyPair(seed []byte, clearkey bool) (*revampedkeypair.RevampedKeyPair, error) {
	if seed == nil {
		return &revampedkeypair.RevampedKeyPair{}, errors.New("Error:Seed must not be null")
	}
	if len(seed) != GetSeedBytesLength() {
		return &revampedkeypair.RevampedKeyPair{}, errors.New("Error:Seed length mismatch")
	}

	pub := make([]byte, GetPublicKeyBytesLength())
	sec := make([]byte, GetSecretKeyBytesLength())

	C.crypto_box_seed_keypair(
		(*C.uchar)(unsafe.Pointer(&pub[0])),
		(*C.uchar)(unsafe.Pointer(&sec[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])),
	)

	if clearkey {
		sodiumsecurememory.MemZero(seed)
	}

	mykeypair, myerrors := revampedkeypair.NewRevampedKeyPair(pub, sec)

	return mykeypair, myerrors
}

func GenerateNonce() []byte {
	return sodiumrng.GetRandomBytes(GetNonceBytesLength())
}

func Create(
	message []byte,
	nonce []byte,
	currentSecret []byte,
	otherPublic []byte,
	clearKey bool,
) ([]byte, error) {

	if currentSecret == nil || len(currentSecret) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret key length invalid")
	}
	if otherPublic == nil || len(otherPublic) != GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length invalid")
	}
	if nonce == nil || len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}

	cipher := make([]byte, len(message)+GetMACBytesLength())

	ret := C.crypto_box_easy(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherPublic[0])),
		(*C.uchar)(unsafe.Pointer(&currentSecret[0])),
	)

	if clearKey {
		sodiumsecurememory.MemZero(currentSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create PublicKeyBox")
	}

	return cipher, nil
}

func CreatePtr(
	message []byte,
	nonce []byte,
	currentSecret unsafe.Pointer,
	otherPublic []byte,
	clearKey bool,
) ([]byte, error) {

	if currentSecret == nil {
		return nil, errors.New("Error: Secret key must not be null")
	}
	if otherPublic == nil || len(otherPublic) != GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length invalid")
	}
	if nonce == nil || len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}

	cipher := make([]byte, len(message)+GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentSecret)

	ret := C.crypto_box_easy(
		(*C.uchar)(unsafe.Pointer(&cipher[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherPublic[0])),
		(*C.uchar)(currentSecret),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentSecret)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentSecret)
		sodiumguardedheapallocation.SodiumFree(currentSecret)
	}

	if ret != 0 {
		return nil, errors.New("Failed to create PublicKeyBox")
	}

	return cipher, nil
}

func PublicKeyBoxOpen(
	cipherText []byte,
	nonce []byte,
	currentUserSecretKey unsafe.Pointer,
	otherUserPublicKey []byte,
	clearKey bool,
) ([]byte, error) {

	if currentUserSecretKey == nil {
		return nil, errors.New("Error: Secret key must not be null/empty")
	}
	if otherUserPublicKey == nil || len(otherUserPublicKey) != GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length mismatch")
	}
	if nonce == nil || len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length mismatch")
	}
	if len(cipherText) < GetMACBytesLength() {
		return nil, errors.New("Error: CipherText too short")
	}

	// ---- legacy trim logic ----
	if cipherText[0] == 0 {
		trim := true
		for i := 0; i < GetMACBytesLength()-1; i++ {
			if cipherText[i] != 0 {
				trim = false
				break
			}
		}
		if trim {
			cipherText = cipherText[GetMACBytesLength():]
		}
	}

	message := make([]byte, len(cipherText)-GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentUserSecretKey)

	ret := C.crypto_box_open_easy(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(currentUserSecretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentUserSecretKey)

	if ret != 0 {
		return nil, errors.New("Failed to open PublicKeyBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentUserSecretKey)
		sodiumguardedheapallocation.SodiumFree(currentUserSecretKey)
	}

	return message, nil
}

func PublicKeyBoxCreateDetached(
	message []byte,
	nonce []byte,
	currentUserSecretKey []byte,
	otherUserPublicKey []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if len(currentUserSecretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret key length mismatch")
	}
	if len(otherUserPublicKey) != GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public key length mismatch")
	}
	if len(nonce) != GetNonceBytesLength() {
		return nil, errors.New("Error: Nonce length mismatch")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, GetMACBytesLength())

	ret := C.crypto_box_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(unsafe.Pointer(&currentUserSecretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to create detached PublicKeyBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(currentUserSecretKey)
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func PublicKeyBoxCreateDetachedPtr(
	message []byte,
	nonce []byte,
	currentUserSecretKey unsafe.Pointer,
	otherUserPublicKey []byte,
	clearKey bool,
) (*detachedbox.DetachedBox, error) {

	if currentUserSecretKey == nil {
		return nil, errors.New("Error: Secret key must not be null")
	}

	cipherText := make([]byte, len(message))
	mac := make([]byte, GetMACBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentUserSecretKey)

	ret := C.crypto_box_detached(
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(currentUserSecretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentUserSecretKey)

	if ret != 0 {
		return nil, errors.New("Failed to create detached PublicKeyBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentUserSecretKey)
		sodiumguardedheapallocation.SodiumFree(currentUserSecretKey)
	}

	return detachedbox.NewDetachedBox(cipherText, mac), nil
}

func PublicKeyBoxOpenDetached(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	currentUserSecretKey []byte,
	otherUserPublicKey []byte,
	clearKey bool,
) ([]byte, error) {

	if len(currentUserSecretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret key length mismatch")
	}
	if len(mac) != GetMACBytesLength() {
		return nil, errors.New("Error: MAC length mismatch")
	}

	message := make([]byte, len(cipherText))

	ret := C.crypto_box_open_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(unsafe.Pointer(&currentUserSecretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to open detached PublicKeyBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(currentUserSecretKey)
	}

	return message, nil
}

func PublicKeyBoxOpenDetachedPtr(
	cipherText []byte,
	mac []byte,
	nonce []byte,
	currentUserSecretKey unsafe.Pointer,
	otherUserPublicKey []byte,
	clearKey bool,
) ([]byte, error) {

	if currentUserSecretKey == nil {
		return nil, errors.New("Error: Secret key must not be null")
	}

	message := make([]byte, len(cipherText))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(currentUserSecretKey)

	ret := C.crypto_box_open_detached(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(*C.uchar)(unsafe.Pointer(&cipherText[0])),
		(*C.uchar)(unsafe.Pointer(&mac[0])),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&otherUserPublicKey[0])),
		(*C.uchar)(currentUserSecretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(currentUserSecretKey)

	if ret != 0 {
		return nil, errors.New("Failed to open detached PublicKeyBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(currentUserSecretKey)
		sodiumguardedheapallocation.SodiumFree(currentUserSecretKey)
	}

	return message, nil
}
