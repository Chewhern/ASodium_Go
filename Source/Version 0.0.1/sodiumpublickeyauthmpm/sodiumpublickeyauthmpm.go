package sodiumpublickeyauthmpm

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumpublickeyauth"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

/* -------------------- Length helpers -------------------- */

func GetStateBytesLength() int {
	return int(C.crypto_sign_statebytes())
}

/* -------------------- State initialization -------------------- */

func InitializeState() ([]byte, error) {
	state := make([]byte, GetStateBytesLength())

	ret := C.crypto_sign_init(
		(*C.crypto_sign_state)(unsafe.Pointer(&state[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to initialize state")
	}

	return state, nil
}

/* -------------------- Update state -------------------- */

func UpdateState(oldState []byte, message []byte) ([]byte, error) {
	if message == nil {
		return nil, errors.New("Error: Message cannot be null")
	}

	if oldState == nil {
		return nil, errors.New("Error: State cannot be null")
	}

	if len(oldState) != GetStateBytesLength() {
		return nil, errors.New(
			"Error: State length must be " +
				string(GetStateBytesLength()) +
				" bytes in length",
		)
	}

	// Same behavior as C#: state mutated in-place
	newState := oldState

	ret := C.crypto_sign_update(
		(*C.crypto_sign_state)(unsafe.Pointer(&newState[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to update state")
	}

	return newState, nil
}

/* -------------------- Final sign (byte[] key) -------------------- */

func SignFinalState(
	state []byte,
	secretKey []byte,
	clearKey bool,
) ([]byte, error) {

	signature := make([]byte, sodiumpublickeyauth.GetSignatureBytesLength())

	ret := C.crypto_sign_final_create(
		(*C.crypto_sign_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		nil, // libsodium allows NULL siglen
		(*C.uchar)(unsafe.Pointer(&secretKey[0])),
	)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign state and create signature")
	}

	if clearKey {
		sodiumsecurememory.MemZero(secretKey)
	}

	return signature, nil
}

/* -------------------- Final sign (IntPtr / guarded heap key) -------------------- */

func SignFinalStatePtr(
	state []byte,
	secretKey unsafe.Pointer,
	clearKey bool,
) ([]byte, error) {

	signature := make([]byte, sodiumpublickeyauth.GetSignatureBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(secretKey)

	ret := C.crypto_sign_final_create(
		(*C.crypto_sign_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		nil,
		(*C.uchar)(secretKey),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(secretKey)

	if ret != 0 {
		return nil, errors.New("Error: Failed to sign state and create signature")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(secretKey)
		sodiumguardedheapallocation.SodiumFree(secretKey)
	}

	return signature, nil
}

/* -------------------- Verify final signed state -------------------- */

func VerifySignedFinalState(
	state []byte,
	signature []byte,
	publicKey []byte,
) (bool, error) {

	if state == nil {
		return false, errors.New("Error: State cannot be null")
	}
	if len(state) != GetStateBytesLength() {
		return false, errors.New(
			"Error: State length must be " +
				string(GetStateBytesLength()) +
				" bytes in length",
		)
	}

	if signature == nil {
		return false, errors.New("Error: Signature cannot be null")
	}
	if len(signature) != sodiumpublickeyauth.GetSignatureBytesLength() {
		return false, errors.New(
			"Error: Signature length must be " +
				string(sodiumpublickeyauth.GetSignatureBytesLength()) +
				" bytes in length",
		)
	}

	if publicKey == nil {
		return false, errors.New("Error: Public Key cannot be null")
	}
	if len(publicKey) != sodiumpublickeyauth.GetPublicKeyBytesLength() {
		return false, errors.New(
			"Error: Public Key length must be " +
				string(sodiumpublickeyauth.GetPublicKeyBytesLength()) +
				" bytes in length",
		)
	}

	ret := C.crypto_sign_final_verify(
		(*C.crypto_sign_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)

	if ret != 0 {
		return false, nil
	}

	return true, nil
}
