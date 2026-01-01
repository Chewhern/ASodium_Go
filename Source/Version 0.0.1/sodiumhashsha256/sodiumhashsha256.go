package sodiumhashsha256

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"fmt"
	"unsafe"
)

func GetComputedHashLength() int {
	return int(C.crypto_hash_sha256_bytes())
}

func GetStateBytesLength() int {
	return int(C.crypto_hash_sha256_statebytes())
}

func ComputeHash(message []byte) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("message must not be nil")
	}

	out := make([]byte, GetComputedHashLength())

	rc := C.crypto_hash_sha256(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to compute hash using SHA-256")
	}

	return out, nil
}

func InitializeState() ([]byte, error) {
	state := make([]byte, GetStateBytesLength())

	rc := C.crypto_hash_sha256_init(
		(*C.crypto_hash_sha256_state)(unsafe.Pointer(&state[0])),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to initialize SHA-256 state")
	}

	return state, nil
}

func UpdateState(state []byte, message []byte) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("state must not be nil")
	}
	if len(state) != GetStateBytesLength() {
		return nil, fmt.Errorf(
			"state length must be %d bytes",
			GetStateBytesLength(),
		)
	}
	if message == nil {
		return nil, fmt.Errorf("message must not be nil")
	}

	rc := C.crypto_hash_sha256_update(
		(*C.crypto_hash_sha256_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.ulonglong(len(message)),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to update SHA-256 state")
	}

	return state, nil
}

func ComputeHashForFinalizedState(state []byte) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("state must not be nil")
	}
	if len(state) != GetStateBytesLength() {
		return nil, fmt.Errorf(
			"state length must be %d bytes",
			GetStateBytesLength(),
		)
	}

	out := make([]byte, GetComputedHashLength())

	rc := C.crypto_hash_sha256_final(
		(*C.crypto_hash_sha256_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)

	if rc != 0 {
		return nil, fmt.Errorf("failed to finalize SHA-256 hash")
	}

	return out, nil
}
