package sodiumstreamcipherxsalsa20

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

func GetXSalsa20KeyBytesLength() int {
	return int(C.crypto_stream_xsalsa20_keybytes())
}

func GetXSalsa20NonceBytesLength() int {
	return int(C.crypto_stream_xsalsa20_noncebytes())
}

func XSalsa20GenerateKey() []byte {
	key := make([]byte, GetXSalsa20KeyBytesLength())
	C.crypto_stream_xsalsa20_keygen((*C.uchar)(&key[0]))
	return key
}

func XSalsa20GenerateKeyPtr() unsafe.Pointer {
	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetXSalsa20KeyBytesLength())
	if isZero {
		return nil
	}

	C.crypto_stream_xsalsa20_keygen((*C.uchar)(keyPtr))
	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	return keyPtr
}

func GenerateXSalsa20Nonce() []byte {
	return sodiumrng.GetRandomBytes(GetXSalsa20NonceBytesLength())
}

func XSalsa20Encrypt(
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
	if len(nonce) != GetXSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXSalsa20NonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != GetXSalsa20KeyBytesLength() {
		return nil, errors.New("Error: Key Length must exactly be " +
			strconv.Itoa(GetXSalsa20KeyBytesLength()) + " bytes")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_xsalsa20_xor(
		(*C.uchar)(&output[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]),
	)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using XSalsa20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func XSalsa20EncryptPtr(
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
	if len(nonce) != GetXSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXSalsa20NonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_xsalsa20_xor(
		(*C.uchar)(&output[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using XSalsa20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func XSalsa20Decrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return XSalsa20Encrypt(cipherText, nonce, key, clearKey)
}

func XSalsa20DecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return XSalsa20EncryptPtr(cipherText, nonce, key, clearKey)
}

func XSalsa20StraightEncrypt(
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
	if len(nonce) != GetXSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXSalsa20NonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != GetXSalsa20KeyBytesLength() {
		return nil, errors.New("Error: Key Length must exactly be " +
			strconv.Itoa(GetXSalsa20KeyBytesLength()) + " bytes")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_xsalsa20_xor_ic(
		(*C.uchar)(&output[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&nonce[0]),
		C.uint64_t(ic),
		(*C.uchar)(&key[0]),
	)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using XSalsa20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func XSalsa20StraightEncryptPtr(
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
	if len(nonce) != GetXSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce Length must exactly be " +
			strconv.Itoa(GetXSalsa20NonceBytesLength()) + " bytes")
	}

	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_stream_xsalsa20_xor_ic(
		(*C.uchar)(&output[0]),
		(*C.uchar)(&message[0]),
		C.ulonglong(len(message)),
		(*C.uchar)(&nonce[0]),
		C.uint64_t(ic),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to straight encrypt using XSalsa20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func XSalsa20StraightDecrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return XSalsa20StraightEncrypt(cipherText, nonce, key, ic, clearKey)
}

func XSalsa20StraightDecryptPtr(
	cipherText []byte,
	nonce []byte,
	key unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return XSalsa20StraightEncryptPtr(cipherText, nonce, key, ic, clearKey)
}
