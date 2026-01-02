package sodiumstreamciphersalsa20128

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"ASodium/sodiumstreamciphersalsa20"
	"errors"
	"unsafe"
)

func GenerateSalsa20Key() []byte {
	return sodiumstreamciphersalsa20.Salsa20GenerateKey()
}

func GenerateSalsa20KeyPtr() unsafe.Pointer {
	return sodiumstreamciphersalsa20.Salsa20GenerateKeyIntPtr()
}

func GenerateSalsa20Nonce() []byte {
	return sodiumstreamciphersalsa20.GenerateSalsa20Nonce()
}

func Salsa2012RoundsEncrypt(
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
	if len(nonce) != int(C.crypto_stream_salsa20_NONCEBYTES) {
		return nil, errors.New("Error: Nonce Length must exactly be crypto_stream_salsa20_NONCEBYTES")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != int(C.crypto_stream_salsa20_KEYBYTES) {
		return nil, errors.New("Error: Key Length must exactly be crypto_stream_salsa20_KEYBYTES")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_salsa2012_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher which operates with 12 rounds")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func Salsa2012RoundsEncryptPtr(
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
	if len(nonce) != int(C.crypto_stream_salsa20_NONCEBYTES) {
		return nil, errors.New("Error: Nonce Length must exactly be crypto_stream_salsa20_NONCEBYTES")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	ret := C.crypto_stream_salsa2012_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher which operates with 12 rounds")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func Salsa2012RoundsDecrypt(
	cipher []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return Salsa2012RoundsEncrypt(cipher, nonce, key, clearKey)
}

func Salsa2012RoundsDecryptPtr(
	cipher []byte,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return Salsa2012RoundsEncryptPtr(cipher, nonce, key, clearKey)
}

/* =========================
   Salsa20/8 (8 rounds)
========================= */

func Salsa208RoundsEncrypt(
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
	if len(nonce) != int(C.crypto_stream_salsa20_NONCEBYTES) {
		return nil, errors.New("Error: Nonce Length must exactly be crypto_stream_salsa20_NONCEBYTES")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}
	if len(key) != int(C.crypto_stream_salsa20_KEYBYTES) {
		return nil, errors.New("Error: Key Length must exactly be crypto_stream_salsa20_KEYBYTES")
	}

	output := make([]byte, len(message))

	ret := C.crypto_stream_salsa208_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher which operates with 8 rounds")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func Salsa208RoundsEncryptPtr(
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
	if len(nonce) != int(C.crypto_stream_salsa20_NONCEBYTES) {
		return nil, errors.New("Error: Nonce Length must exactly be crypto_stream_salsa20_NONCEBYTES")
	}
	if key == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)
	ret := C.crypto_stream_salsa208_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(key),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher which operates with 8 rounds")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return output, nil
}

func Salsa208RoundsDecrypt(
	cipher []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return Salsa208RoundsEncrypt(cipher, nonce, key, clearKey)
}

func Salsa208RoundsDecryptPtr(
	cipher []byte,
	nonce []byte,
	key unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return Salsa208RoundsEncryptPtr(cipher, nonce, key, clearKey)
}
