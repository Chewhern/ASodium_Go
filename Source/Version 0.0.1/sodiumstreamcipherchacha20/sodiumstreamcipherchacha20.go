package sodiumstreamcipherchacha20

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"strconv"
	"unsafe"
)

func GetChaCha20KeyBytesLength() int {
	return int(C.crypto_stream_chacha20_keybytes())
}

func GetChaCha20NonceBytesLength() int {
	return int(C.crypto_stream_chacha20_noncebytes())
}

func GetChaCha20IETFKeyBytesLength() int {
	return int(C.crypto_stream_chacha20_ietf_keybytes())
}

func GetChaCha20IETFNonceBytesLength() int {
	return int(C.crypto_stream_chacha20_ietf_noncebytes())
}

func GetChaCha20IETFMaxMessageLength() int64 {
	return int64(C.crypto_stream_chacha20_ietf_messagebytes_max())
}

func ChaCha20GenerateKey() []byte {
	return sodiumrng.GetRandomBytes(GetChaCha20KeyBytesLength())
}

func ChaCha20GenerateKeyPtr() unsafe.Pointer {
	keyPtr := sodiumrng.GetRandomBytesPtr(GetChaCha20KeyBytesLength())
	if keyPtr != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	}
	return keyPtr
}

func ChaCha20IETFGenerateKey() []byte {
	return sodiumrng.GetRandomBytes(GetChaCha20IETFKeyBytesLength())
}

func ChaCha20IETFGenerateKeyPtr() unsafe.Pointer {
	keyPtr := sodiumrng.GetRandomBytesPtr(GetChaCha20IETFKeyBytesLength())
	if keyPtr != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	}
	return keyPtr
}

func GenerateChaCha20Nonce() []byte {
	return sodiumrng.GetRandomBytes(GetChaCha20NonceBytesLength())
}

func GenerateChaCha20IETFNonce() []byte {
	return sodiumrng.GetRandomBytes(GetChaCha20IETFNonceBytesLength())
}

func ChaCha20Encrypt(message []byte, nonce []byte, key []byte, clearKey bool) ([]byte, error) {
	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != GetChaCha20KeyBytesLength() {
		return nil, errors.New("Error: Key length invalid")
	}

	output := make([]byte, len(message))

	result := C.crypto_stream_chacha20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if result != 0 {
		return nil, errors.New("Failed to encrypt using ChaCha20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

/* =======================
   Encryption (guarded key)
   ======================= */

func ChaCha20EncryptPtr(message []byte, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	result := C.crypto_stream_chacha20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if result != 0 {
		return nil, errors.New("Failed to encrypt using ChaCha20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return output, nil
}

func ChaCha20Decrypt(cipherText []byte, nonce []byte, key []byte, clearKey bool) ([]byte, error) {
	return ChaCha20Encrypt(cipherText, nonce, key, clearKey)
}

func ChaCha20DecryptPtr(cipherText []byte, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	return ChaCha20EncryptPtr(cipherText, nonce, keyPtr, clearKey)
}

func ChaCha20IETFEncrypt(message, nonce, key []byte, clearKey bool) ([]byte, error) {
	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetChaCha20IETFNonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != GetChaCha20IETFKeyBytesLength() {
		return nil, errors.New("Error: Key length invalid")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_chacha20_ietf_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using ChaCha20 IETF stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func ChaCha20IETFEncryptPtr(message, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetChaCha20IETFNonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)
	ret := C.crypto_stream_chacha20_ietf_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using ChaCha20 IETF stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return output, nil
}

func ChaCha20IETFDecrypt(cipher, nonce, key []byte, clearKey bool) ([]byte, error) {
	return ChaCha20IETFEncrypt(cipher, nonce, key, clearKey)
}

func ChaCha20IETFDecryptPtr(cipher, nonce []byte, keyPtr unsafe.Pointer, clearKey bool) ([]byte, error) {
	return ChaCha20IETFEncryptPtr(cipher, nonce, keyPtr, clearKey)
}

func ChaCha20StraightEncrypt(message, nonce, key []byte, ic uint64, clearKey bool) ([]byte, error) {
	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != GetChaCha20KeyBytesLength() {
		return nil, errors.New("Error: Key length invalid")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_chacha20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint64_t(ic),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using ChaCha20")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func ChaCha20StraightEncryptPtr(
	message []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("Error: Message must not be null")
	}
	if len(message) == 0 {
		return nil, errors.New("Error: Message Length must not be 0")
	}

	if nonce == nil {
		return nil, errors.New("Error: Nonce must not be null")
	}
	if len(nonce) != GetChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " + strconv.Itoa(GetChaCha20NonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_chacha20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint64_t(ic),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using ChaCha20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func ChaCha20StraightDecrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return ChaCha20StraightEncrypt(cipherText, nonce, key, ic, clearKey)
}

func ChaCha20StraightDecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return ChaCha20StraightEncryptPtr(cipherText, nonce, key, ic, clearKey)
}

func ChaCha20IETFStraightEncrypt(
	message []byte,
	nonce []byte,
	key []byte,
	ic uint32,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("Error: Message must not be null")
	}
	if len(message) == 0 {
		return nil, errors.New("Error: Message Length must not be 0")
	}

	if nonce == nil {
		return nil, errors.New("Error: Nonce must not be null")
	}
	if len(nonce) != GetChaCha20IETFNonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " + strconv.Itoa(GetChaCha20IETFNonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != GetChaCha20IETFKeyBytesLength() {
		return nil, errors.New("Error: Key Length must exactly be " + strconv.Itoa(GetChaCha20IETFKeyBytesLength()) + " bytes")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_chacha20_ietf_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint32_t(ic),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using ChaCha20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func ChaCha20IETFStraightEncryptPtr(
	message []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint32,
	clearKey bool,
) ([]byte, error) {

	if message == nil {
		return nil, errors.New("Error: Message must not be null")
	}
	if len(message) == 0 {
		return nil, errors.New("Error: Message Length must not be 0")
	}

	if nonce == nil {
		return nil, errors.New("Error: Nonce must not be null")
	}
	if len(nonce) != GetChaCha20IETFNonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " + strconv.Itoa(GetChaCha20IETFNonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_chacha20_ietf_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint32_t(ic),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using ChaCha20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func ChaCha20IETFStraightDecrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	ic uint32,
	clearKey bool,
) ([]byte, error) {
	return ChaCha20IETFStraightEncrypt(cipherText, nonce, key, ic, clearKey)
}

func ChaCha20IETFStraightDecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint32,
	clearKey bool,
) ([]byte, error) {
	return ChaCha20IETFStraightEncryptPtr(cipherText, nonce, key, ic, clearKey)
}
