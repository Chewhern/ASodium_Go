package sodiumstreamcipherxchacha20

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

func GetXChaCha20KeyBytesLength() int {
	return int(C.crypto_stream_xchacha20_keybytes())
}

func GetXChaCha20NonceBytesLength() int {
	return int(C.crypto_stream_xchacha20_noncebytes())
}

func XChaCha20GenerateKey() []byte {
	key := make([]byte, GetXChaCha20KeyBytesLength())
	C.crypto_stream_xchacha20_keygen(
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)
	return key
}

func XChaCha20GenerateKeyPtr() unsafe.Pointer {
	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetXChaCha20KeyBytesLength())

	if !isZero {
		C.crypto_stream_xchacha20_keygen((*C.uchar)(keyPtr))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
		return keyPtr
	}

	return nil
}

func GenerateXChaCha20Nonce() []byte {
	return sodiumrng.GetRandomBytes(GetXChaCha20NonceBytesLength())
}

func XChaCha20Encrypt(
	message []byte,
	nonce []byte,
	key []byte,
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
	if len(nonce) != GetXChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXChaCha20NonceBytesLength()) + " bytes")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != GetXChaCha20KeyBytesLength() {
		return nil, errors.New("Error: Key Length must exactly be " +
			strconv.Itoa(GetXChaCha20KeyBytesLength()) + " bytes")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_xchacha20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using XChaCha20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func XChaCha20EncryptPtr(
	message []byte,
	nonce []byte,
	key unsafe.Pointer,
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
	if len(nonce) != GetXChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXChaCha20NonceBytesLength()) + " bytes")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_xchacha20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using XChaCha20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func XChaCha20Decrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return XChaCha20Encrypt(cipherText, nonce, key, clearKey)
}

func XChaCha20DecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return XChaCha20EncryptPtr(cipherText, nonce, key, clearKey)
}

func XChaCha20StraightEncrypt(
	message []byte,
	nonce []byte,
	key []byte,
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
	if len(nonce) != GetXChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXChaCha20NonceBytesLength()) + " bytes")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != GetXChaCha20KeyBytesLength() {
		return nil, errors.New("Error: Key Length must exactly be " +
			strconv.Itoa(GetXChaCha20KeyBytesLength()) + " bytes")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_xchacha20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint64_t(ic),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using XChaCha20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func XChaCha20StraightEncryptPtr(
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
	if len(nonce) != GetXChaCha20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXChaCha20NonceBytesLength()) + " bytes")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_xchacha20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.uint64_t(ic),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using XChaCha20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func XChaCha20StraightDecrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return XChaCha20StraightEncrypt(cipherText, nonce, key, ic, clearKey)
}

func XChaCha20StraightDecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return XChaCha20StraightEncryptPtr(cipherText, nonce, key, ic, clearKey)
}
