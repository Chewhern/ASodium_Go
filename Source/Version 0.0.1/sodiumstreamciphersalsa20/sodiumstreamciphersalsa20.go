package sodiumstreamciphersalsa20

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

/* ---------- Size helpers ---------- */

func GetSalsa20KeyBytesLength() int {
	return int(C.crypto_stream_salsa20_keybytes())
}

func GetSalsa20NonceBytesLength() int {
	return int(C.crypto_stream_salsa20_noncebytes())
}

/* ---------- Key generation ---------- */

func Salsa20GenerateKey() []byte {
	key := make([]byte, GetSalsa20KeyBytesLength())
	C.crypto_stream_salsa20_keygen((*C.uchar)(unsafe.Pointer(&key[0])))
	return key
}

func Salsa20GenerateKeyIntPtr() unsafe.Pointer {
	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetSalsa20KeyBytesLength())
	if !isZero {
		C.crypto_stream_salsa20_keygen((*C.uchar)(keyPtr))
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
		return keyPtr
	}
	return nil
}

/* ---------- Nonce ---------- */

func GenerateSalsa20Nonce() []byte {
	return sodiumrng.GetRandomBytes(GetSalsa20NonceBytesLength())
}

/* ---------- Encrypt / Decrypt (byte[]) ---------- */

func Salsa20Encrypt(
	message []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != GetSalsa20KeyBytesLength() {
		return nil, errors.New("Error: Key length invalid")
	}

	output := make([]byte, len(message))

	rc := C.crypto_stream_salsa20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if rc != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func Salsa20Decrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {
	return Salsa20Encrypt(cipherText, nonce, key, clearKey)
}

/* ---------- Encrypt / Decrypt (IntPtr key) ---------- */

func Salsa20EncryptPtr(
	message []byte,
	nonce []byte,
	keyPtr unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)

	rc := C.crypto_stream_salsa20_xor(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(keyPtr),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if rc != 0 {
		return nil, errors.New("Failed to encrypt using Salsa20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return output, nil
}

func Salsa20DecryptPtr(
	cipherText []byte,
	nonce []byte,
	keyPtr unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {
	return Salsa20EncryptPtr(cipherText, nonce, keyPtr, clearKey)
}

/* ---------- Straight Encrypt / Decrypt ---------- */

func Salsa20StraightEncrypt(
	message []byte,
	nonce []byte,
	key []byte,
	ic uint64,
	clearKey bool,
) ([]byte, error) {

	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if key == nil || len(key) != GetSalsa20KeyBytesLength() {
		return nil, errors.New("Error: Key length invalid")
	}

	output := make([]byte, len(message))

	rc := C.crypto_stream_salsa20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.ulonglong(ic),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if rc != 0 {
		return nil, errors.New("Failed to straight encrypt using Salsa20 stream cipher")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return output, nil
}

func Salsa20StraightEncryptPtr(
	message []byte,
	nonce []byte,
	keyPtr unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {

	if message == nil || len(message) == 0 {
		return nil, errors.New("Error: Message must not be null or empty")
	}
	if nonce == nil || len(nonce) != GetSalsa20NonceBytesLength() {
		return nil, errors.New("Error: Nonce length invalid")
	}
	if keyPtr == nil {
		return nil, errors.New("Error: Key must not be null")
	}

	output := make([]byte, len(message))

	sodiumguardedheapallocation.SodiumMProtectReadOnly(keyPtr)

	rc := C.crypto_stream_salsa20_xor_ic(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.ulonglong(ic),
		(*C.uchar)(keyPtr),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)

	if rc != 0 {
		return nil, errors.New("Failed to straight encrypt using Salsa20 stream cipher")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(keyPtr)
		sodiumguardedheapallocation.SodiumFree(keyPtr)
	}

	return output, nil
}

func Salsa20StraightDecrypt(
	cipherText []byte,
	nonce []byte,
	key []byte,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return Salsa20StraightEncrypt(cipherText, nonce, key, ic, clearKey)
}

func Salsa20StraightDecryptPtr(
	cipherText []byte,
	nonce []byte,
	keyPtr unsafe.Pointer,
	ic uint64,
	clearKey bool,
) ([]byte, error) {
	return Salsa20StraightEncryptPtr(cipherText, nonce, keyPtr, ic, clearKey)
}
