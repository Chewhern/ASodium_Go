package sodiumpublickeyauth

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/keypair"
	"ASodium/revampedkeypair"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetSeedBytesLength() int {
	return int(C.crypto_sign_seedbytes())
}

func GetPublicKeyBytesLength() int {
	return int(C.crypto_sign_publickeybytes())
}

func GetSecretKeyBytesLength() int {
	return int(C.crypto_sign_secretkeybytes())
}

func GetSignatureBytesLength() int {
	return int(C.crypto_sign_bytes())
}

func GetPrimitiveByte() byte {
	return byte(*C.crypto_sign_primitive())
}

func GenerateKeyPair() *keypair.KeyPair {

	publicKeyPtr, isZero1 := sodiumguardedheapallocation.SodiumMalloc(GetPublicKeyBytesLength())
	secretKeyPtr, isZero2 := sodiumguardedheapallocation.SodiumMalloc(GetSecretKeyBytesLength())

	if !isZero1 && !isZero2 {
		C.crypto_sign_keypair(
			(*C.uchar)(publicKeyPtr),
			(*C.uchar)(secretKeyPtr),
		)

		sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKeyPtr)

		return keypair.NewKeyPair(
			secretKeyPtr,
			GetSecretKeyBytesLength(),
			publicKeyPtr,
			GetPublicKeyBytesLength(),
		)
	}

	return keypair.NewKeyPair(nil, 0, nil, 0)
}

func GenerateRevampedKeyPair() (*revampedkeypair.RevampedKeyPair, error) {
	publicKey := make([]byte, GetPublicKeyBytesLength())
	secretKey := make([]byte, GetSecretKeyBytesLength())

	C.crypto_sign_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	myKeypair, myerror := revampedkeypair.NewRevampedKeyPair(publicKey, secretKey)

	return myKeypair, myerror
}

func GenerateSeededKeyPair(seed unsafe.Pointer, clearKey bool) (*keypair.KeyPair, error) {
	if seed == nil {
		return keypair.NewKeyPairEmpty(), errors.New("Error:Seed must not be null")
	}

	publicKeyPtr, isZero1 := sodiumguardedheapallocation.SodiumMalloc(GetPublicKeyBytesLength())
	secretKeyPtr, isZero2 := sodiumguardedheapallocation.SodiumMalloc(GetSecretKeyBytesLength())

	if !isZero1 && !isZero2 {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(seed)

		C.crypto_sign_seed_keypair(
			(*C.uchar)(publicKeyPtr),
			(*C.uchar)(secretKeyPtr),
			(*C.uchar)(seed),
		)

		sodiumguardedheapallocation.SodiumMProtectNoAccess(seed)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKeyPtr)

		if clearKey {
			sodiumguardedheapallocation.SodiumMProtectReadWrite(seed)
			sodiumguardedheapallocation.SodiumFree(seed)
		}

		return keypair.NewKeyPair(
			secretKeyPtr,
			GetSecretKeyBytesLength(),
			publicKeyPtr,
			GetPublicKeyBytesLength(),
		), nil
	}

	return keypair.NewKeyPair(nil, 0, nil, 0), nil
}

func GenerateSeededRevampedKeyPair(seed []byte) (*revampedkeypair.RevampedKeyPair, error) {
	if seed == nil {
		return &revampedkeypair.RevampedKeyPair{}, errors.New("Error:Seed must not be null")
	}
	if len(seed) != GetSeedBytesLength() {
		return &revampedkeypair.RevampedKeyPair{}, errors.New("Error:Seed length must be exact")
	}

	publicKey := make([]byte, GetPublicKeyBytesLength())
	secretKey := make([]byte, GetSecretKeyBytesLength())

	C.crypto_sign_seed_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
		(*C.uchar)(unsafe.Pointer(&seed[0])),
	)

	myKeypair, myError := revampedkeypair.NewRevampedKeyPair(publicKey, secretKey)

	return myKeypair, myError
}

func Sign(message []byte, secretKey []byte, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}
	if len(secretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret Key length mismatch")
	}

	signatureMessage := make([]byte, GetSignatureBytesLength()+len(message))
	var sigLen C.ulonglong

	ret := C.crypto_sign(
		(*C.uchar)(unsafe.Pointer(&signatureMessage[0])),
		&sigLen,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign message")
	}

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return signatureMessage, nil
}

func SignPtr(message []byte, secretKey unsafe.Pointer, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}

	signatureMessage := make([]byte, GetSignatureBytesLength()+len(message))
	var sigLen C.ulonglong

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)

	ret := C.crypto_sign(
		(*C.uchar)(unsafe.Pointer(&signatureMessage[0])),
		&sigLen,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(secretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign message")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return signatureMessage, nil
}

func Verify(signatureMessage []byte, publicKey []byte) ([]byte, error) {
	if signatureMessage == nil {
		return nil, errors.New("Error: Signature message cannot be null")
	}
	if int64(len(signatureMessage))-int64(GetSignatureBytesLength()) == 0 {
		return nil, errors.New("Error: Signature message is not properly signed")
	}
	if publicKey == nil {
		return nil, errors.New("Error: Public key cannot be null")
	}
	if len(publicKey) != GetPublicKeyBytesLength() {
		return nil, errors.New("Error: Public Key length mismatch")
	}

	message := make([]byte, len(signatureMessage)-GetSignatureBytesLength())
	var msgLen C.ulonglong

	ret := C.crypto_sign_open(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		&msgLen,
		(*C.uchar)(unsafe.Pointer(&signatureMessage[0])),
		C.ulonglong(len(signatureMessage)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to verify signature")
	}

	return message, nil
}

func SignDetached(message []byte, secretKey []byte, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}
	if len(secretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret Key length mismatch")
	}

	signature := make([]byte, GetSignatureBytesLength())
	var sigLen C.ulonglong

	ret := C.crypto_sign_detached(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		&sigLen,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign message and create signature")
	}

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return signature, nil
}

/* ---------- SignDetached (IntPtr) ---------- */

func SignDetachedPtr(message []byte, secretKey unsafe.Pointer, clearKey bool) ([]byte, error) {
	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}

	signature := make([]byte, GetSignatureBytesLength())

	var sigLen C.ulonglong

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)
	ret := C.crypto_sign_detached(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		&sigLen,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(secretKey),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign message and create signature")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return signature, nil
}

/* ---------- VerifyDetached ---------- */

func VerifyDetached(signature, message, publicKey []byte) (bool, error) {
	if signature == nil {
		return false, errors.New("Error: Signature cannot be null")
	}
	if len(signature) != GetSignatureBytesLength() {
		return false, errors.New("Error: Signature length must have " +
			string(GetSignatureBytesLength()) + " bytes in length")
	}

	if message == nil {
		return false, errors.New("Error: Message cannot be null")
	}

	if publicKey == nil {
		return false, errors.New("Error: Public key cannot be null")
	}
	if len(publicKey) != GetPublicKeyBytesLength() {
		return false, errors.New("Error: Public Key length must be correct")
	}

	ret := C.crypto_sign_verify_detached(
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	return ret == 0, nil
}

/* ---------- GeneratePublicKey ---------- */

func GeneratePublicKey(secretKey []byte, clearKey bool) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}
	if len(secretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret Key length must be correct")
	}

	publicKey := make([]byte, GetPublicKeyBytesLength())

	ret := C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to generate public key")
	}

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return publicKey, nil
}

func GeneratePublicKeyPtr(secretKey unsafe.Pointer, clearKey bool) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}

	publicKey := make([]byte, GetPublicKeyBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)
	ret := C.crypto_sign_ed25519_sk_to_pk(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(secretKey),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to generate public key")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return publicKey, nil
}

/* ---------- ExtractSeed ---------- */

func ExtractSeed(secretKey []byte, clearKey bool) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}
	if len(secretKey) != GetSecretKeyBytesLength() {
		return nil, errors.New("Error: Secret Key length must be correct")
	}

	seed := make([]byte, GetSeedBytesLength())

	ret := C.crypto_sign_ed25519_sk_to_seed(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to extract seeds")
	}

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return seed, nil
}

func ExtractSeedPtr(secretKey unsafe.Pointer, clearKey bool) (unsafe.Pointer, error) {
	if secretKey == nil {
		return nil, errors.New("Error: Secret Key cannot be null")
	}

	seedPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetSeedBytesLength())
	if isZero {
		return nil, nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)
	ret := C.crypto_sign_ed25519_sk_to_seed(
		(*C.uchar)(seedPtr),
		(*C.uchar)(secretKey),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to extract seeds")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(seedPtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return seedPtr, nil
}
