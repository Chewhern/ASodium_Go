package sodiumguardedheapallocation

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// SodiumMalloc allocates guarded memory using sodium_malloc
func SodiumMalloc(size int) (ptr unsafe.Pointer, isZero bool) {
	ptr = C.sodium_malloc(C.size_t(size))
	if ptr == nil {
		isZero = true
	} else {
		isZero = false
	}
	return
}

// SodiumAllocArray allocates an array in guarded memory
func SodiumAllocArray(arrayLength, elementSize int) (ptr unsafe.Pointer, isZero bool, err error) {
	if arrayLength < 0 || elementSize < 0 {
		return nil, true, fmt.Errorf("arrayLength or elementSize cannot be negative")
	}

	// Check overflow: elementSize * arrayLength must not exceed uint64 max
	if uint64(elementSize) >= (^(uint64(0)) / uint64(arrayLength)) {
		return nil, true, fmt.Errorf("array element size too large: max allowed is %d", ^uint64(0)/uint64(arrayLength))
	}

	ptr = C.sodium_allocarray(C.size_t(arrayLength), C.size_t(elementSize))
	if ptr == nil {
		isZero = true
	} else {
		isZero = false
	}
	return ptr, isZero, nil
}

// SodiumFree frees memory allocated by sodium_malloc or sodium_allocarray
func SodiumFree(ptr unsafe.Pointer) {
	C.sodium_free(ptr)
}

// SodiumMProtectNoAccess sets memory to no access
func SodiumMProtectNoAccess(ptr unsafe.Pointer) error {
	status := C.sodium_mprotect_noaccess(ptr)
	if status == -1 {
		return fmt.Errorf("pointer is already in no access state")
	}
	return nil
}

// SodiumMProtectReadOnly sets memory to read-only
func SodiumMProtectReadOnly(ptr unsafe.Pointer) error {
	status := C.sodium_mprotect_readonly(ptr)
	if status == -1 {
		return fmt.Errorf("pointer is already in read-only state")
	}
	return nil
}

// SodiumMProtectReadWrite sets memory to read/write
func SodiumMProtectReadWrite(ptr unsafe.Pointer) error {
	status := C.sodium_mprotect_readwrite(ptr)
	if status == -1 {
		return fmt.Errorf("pointer is already in read-write state")
	}
	return nil
}
