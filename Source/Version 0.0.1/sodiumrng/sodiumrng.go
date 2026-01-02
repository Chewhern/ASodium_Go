package sodiumrng

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"fmt"
	"unsafe"
)

func GetSeedBytesValue() int32 {
	return int32(C.randombytes_seedbytes())
}

func GetRandomBytes(count int) []byte {
	buffer := make([]byte, count) // allocate slice
	C.randombytes_buf(unsafe.Pointer(&buffer[0]), C.size_t(count))
	return buffer
}

// GetRandomBytes allocates a protected memory buffer and fills it with random bytes
func GetRandomBytesPtr(count int) unsafe.Pointer {
	isZero := true
	var dataPtr unsafe.Pointer

	for i := 0; i < 5 && isZero; i++ {
		dataPtr, isZero = sodiumguardedheapallocation.SodiumMalloc(count)
		if dataPtr != nil {
			isZero = false
		}
	}

	if isZero {
		return nil
	}

	C.randombytes_buf(dataPtr, C.size_t(count))
	return dataPtr
}

func GetSeededRandomBytes(count int, seed []byte, clearKey bool) ([]byte, error) {
	seedLen := int(C.randombytes_seedbytes())
	if len(seed) != seedLen {
		return nil, fmt.Errorf("seed length must be %d", seedLen)
	}

	const maxCount = 274877766207
	if int64(count) > maxCount {
		return nil, fmt.Errorf("count cannot exceed %d", maxCount)
	}

	buffer := make([]byte, count)
	C.randombytes_buf_deterministic(
		unsafe.Pointer(&buffer[0]),
		C.size_t(count),
		(*C.uchar)(&seed[0]),
	)

	if clearKey {
		sodiumsecurememory.MemZero(seed)
	}

	return buffer, nil
}

func GetSeededRandomBytesPtr(count int, seedPtr unsafe.Pointer, clearKey bool) unsafe.Pointer {
	const maxCount = 274877766207
	if seedPtr == nil {
		return nil
	}
	if int64(count) > maxCount {
		return nil
	}

	// Allocate output buffer
	var dataPtr unsafe.Pointer
	isZero := true
	for i := 0; i < 5 && isZero; i++ {
		dataPtr, isZero = sodiumguardedheapallocation.SodiumMalloc(count)
		if dataPtr != nil {
			isZero = false
		}
	}

	if isZero {
		return nil
	}

	// Protect seed read-only
	C.sodium_mprotect_readonly(seedPtr)
	C.randombytes_buf_deterministic(dataPtr, C.size_t(count), (*C.uchar)(seedPtr))
	C.sodium_mprotect_noaccess(seedPtr)

	if clearKey {
		C.sodium_mprotect_readwrite(seedPtr)
		C.sodium_free(seedPtr)
	}

	return dataPtr
}

func GetUniformUpperBoundRandomNumber(upperBound uint32) (uint32, error) {
	if upperBound < 2 {
		return 0, fmt.Errorf("upper bound must be >= 2")
	}
	return uint32(C.randombytes_uniform(C.uint32_t(upperBound))), nil
}

func GetRandomNumber() uint32 {
	return uint32(C.randombytes_random())
}
