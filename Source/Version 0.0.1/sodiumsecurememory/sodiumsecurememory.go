package sodiumsecurememory

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// MemZero zeroes memory for a given slice
func MemZero(buf []byte) {
	if len(buf) > 0 {
		C.sodium_memzero(unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}
}

// MemZeroPtr zeroes memory for an unsafe pointer of given length
func MemZeroPtr(ptr unsafe.Pointer, length int) {
	if ptr != nil && length > 0 {
		C.sodium_memzero(ptr, C.size_t(length))
	}
}

// MemLockPtr locks memory pointed by ptr for length bytes
func MemLockPtr(ptr unsafe.Pointer, length int) error {
	if ptr == nil || length <= 0 {
		return fmt.Errorf("invalid pointer or length")
	}
	status := C.sodium_mlock(ptr, C.size_t(length))
	if status != 0 {
		return fmt.Errorf("memory lock failed: requested length may exceed system limit")
	}
	return nil
}

// MemUnlockPtr unlocks memory pointed by ptr for length bytes
func MemUnlockPtr(ptr unsafe.Pointer, length int) error {
	if ptr == nil || length <= 0 {
		return fmt.Errorf("invalid pointer or length")
	}
	status := C.sodium_munlock(ptr, C.size_t(length))
	if status != 0 {
		return fmt.Errorf("memory unlock failed")
	}
	return nil
}

//Unable to replicate C# address pinning from any data type's object
//meaning it'll be best to avoid storing passwords or any sensitive data in strings
