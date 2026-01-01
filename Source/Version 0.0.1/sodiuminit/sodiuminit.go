package sodiuminit

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"sync"
)

var (
	initOnce sync.Once
)

// init() is the Go equivalent of a C# static constructor
func init() {
	Init()
}

// Init initializes libsodium exactly once
func Init() {
	initOnce.Do(func() {
		// sodium_init returns >= 0 on success
		if C.sodium_init() < 0 {
			panic("libsodium initialization failed")
		}
	})
}

// SodiumVersionString returns the libsodium version string
func SodiumVersionString() string {
	ptr := C.sodium_version_string()
	return C.GoString(ptr)
}
